# Kế hoạch MVP

## Mục tiêu và kiến trúc đã chốt

Hai Worker trong cùng Cloudflare account, D1, UI tĩnh phục vụ cùng Service A, và adapter chạy cùng ứng dụng client. Chưa cần Durable Objects cho MVP một client kết nối một Gateway. Giới hạn đồng thời chính xác toàn hệ thống cần cơ chế điều phối bổ sung. Hai Worker chia sẻ quota tài khoản; WebSocket không loại bỏ CPU/subrequest limits.

Luồng: ứng dụng → HTTP loopback của adapter → WSS Gateway → provider allowlist. Adapter lấy access token ngắn hạn từ Identity; Gateway xác minh token và quyền credential trước khi gọi provider. Adapter chuyển stream upstream sang SSE OpenAI-compatible.

## Service A — Identity & Config

- UI đăng nhập Google hoặc OIDC provider cấu hình sẵn; chỉ user trong allowlist được sử dụng.
- Quản lý user, project, client; quyền theo provider/model; cấp token Gateway ngắn hạn, refresh/revoke session, rotate client secret.
- Backend/agent runtime giữ được secret: OAuth client credentials (`client_id` + `client_secret`). Browser/mobile/CLI phân phối: Authorization Code + PKCE hoặc pairing phù hợp, không nhúng shared secret.
- OIDC xác định người đăng nhập; machine credentials không thay thế danh tính user. Chốt mô hình principal/delegation để credential luôn có đúng user/project sở hữu.
- Quản lý provider, model alias, payload/concurrency/session limits; bootstrap export không chứa raw secret.
- MVP không mặc định biến A thành OIDC issuer. Nếu cần issuer: discovery, JWKS, authorize/token/userinfo và protocol tests với thư viện đã được kiểm chứng.

## Credential envelope

User gửi API key qua HTTPS từ UI đã đăng nhập. Backend mã hoá AES-GCM, trả envelope cho adapter lưu local. Authenticated metadata gồm credentialId, user/project, provider, encryption key version và expiry; mỗi lần mã hoá dùng nonce mới. Khoá hệ thống chỉ nằm trong Worker Secrets.

Adapter trình access token và envelope khi mở phiên qua cơ chế được chốt trong contract. Gateway kiểm tra ownership, quyền, expiry, trạng thái revoke và giải mã để gọi provider. Raw key chỉ tồn tại tạm trong bộ nhớ, không trả lại client hay ghi log. Envelope cần token hợp lệ; đây không phải mã hoá đầu-cuối che key khỏi backend.

Mặc định D1 chỉ lưu metadata và trạng thái revoke; client giữ envelope, mất thì nhập lại key. Đồng bộ bản mã nhiều thiết bị là tuỳ chọn riêng. Xoá bản local không revoke bản sao: revoke credentialId hoặc rotate key tại provider. Chốt rotation, migration/expiry của envelope cũ và quyền decrypt giữa hai Worker trước khi code.

## Service B — LLM Socket Gateway

Adapter mở WSS với token qua Authorization header; không đặt token dài hạn trong URL. Gateway xác minh signature, issuer, audience, expiry và quyền; credential phải thuộc đúng user/project.

Một socket chứa nhiều tác vụ với requestId riêng; response chunk có sequence. Protocol v1: `session.ready`, `request.start`, `response.chunk`, `response.end`, `response.error`, `request.cancel`, `session.draining`.

Gateway ưu tiên chuyển tiếp chunk upstream ít biến đổi; adapter xử lý chuyển đổi OpenAI/Anthropic. Chỉ gọi provider/endpoint allowlist, không nhận URL upstream tuỳ ý. Bound kích thước message/payload, buffer, concurrency và thời gian phiên. Client chậm phải kích hoạt backpressure hoặc huỷ upstream; disconnect/cancel phải dọn tài nguyên.

Token hết hạn phải reauthenticate hoặc đóng theo policy rõ ràng. Gateway không tự retry LLM. Retry thuộc client, không nối âm thầm attempt mới vào stream đang dở vì upstream có thể đã xử lý/tính phí.

## Local Adapter

Package chạy cùng OpenCode/ứng dụng; trong ChatGPT Cloud chạy trong chính môi trường cloud đó, bind loopback. MVP `/v1/models` và `/v1/chat/completions`, hỗ trợ text, tool calls và usage khi provider có. `/v1/responses` là contract riêng; yêu cầu client đã được xác nhận và thiết kế generation stateless được chốt tại ADR 0003. Adapter 0.3.0 bổ sung Responses và legacy `/v1/completions` cho provider OpenAI-protocol; Chat Completions tiếp tục hỗ trợ OpenAI/Anthropic.

Chốt cách bảo vệ local API, lưu envelope/token, SSE error mapping, cancellation, reconnect và retry trước khi triển khai. Mỗi attempt cần danh tính rõ ràng và lỗi ngắt stream phải đến được ứng dụng.

## UI và dữ liệu

Năm màn hình: Dashboard (kết nối, lỗi, usage ước tính); Clients (tạo, quyền, rotate/revoke, config download); Providers (key/OAuth đủ điều kiện, model, test kết nối); Sessions (thiết bị, expiry, revoke); Security (OIDC, user allowlist, key versions, audit).

D1: user/project/client/provider, credential metadata, session, audit tối thiểu. Không lưu prompt, response hoặc raw API key mặc định. Thiết kế quyền đọc/ghi D1 giữa các Worker, revoke propagation và retention phải được ghi lại. Usage chỉ là ước tính khi thiếu dữ liệu provider.

## OAuth provider — mở rộng có điều kiện

Tách login hệ thống khỏi uỷ quyền dùng LLM. MVP OpenAI/Claude dùng API key. Chỉ bật nút OAuth khi connector đã được xác minh hỗ trợ; ghi nguồn và ngày xác minh.

OpenAI Sign in with ChatGPT có điều kiện cho ứng dụng mã nguồn mở/local; phải xác minh riêng remote-hosted Cloudflare proxy. Không mặc định local token sharing áp dụng cho proxy. Claude dùng Console API key hoặc cloud provider được hỗ trợ; không cam kết subscription Pro/Max dùng được. Nếu provider cấp refresh token, chọn đúng một đầu chịu trách nhiệm refresh/rotation để tránh race.

## Giai đoạn và tiêu chí hoàn thành

### 1. Contract và kiểm chứng Workers Free

- Chốt auth flows, principal/claims, token signing/JWKS/rotation, quyền và thời điểm revoke có hiệu lực.
- Chốt envelope encoding/AAD, nonce, key versions, expiry, ownership và rotation.
- Chốt WebSocket schemas, handshake/envelope transport, requestId uniqueness, chunk ordering, terminal states, cancel races, errors, draining, token expiry và slow-client policy.
- Viết threat model cho UI/OIDC, machine/public clients, local API, envelope, cross-tenant access, SSRF, replay, resource exhaustion và logs.
- Chọn tooling/layout và một provider API key để prototype stream.
- Benchmark thực trên Workers Free với 1/5/10 tác vụ mỗi socket: ghi cấu hình, payload, model, phiên bản, ngày chạy, CPU/latency/memory có thể quan sát, lỗi và giới hạn phương pháp đo. Không suy diễn capacity guarantee từ mốc 10.

Hoàn thành khi contract/threat model được ghi rõ và có bằng chứng benchmark thật; phần chưa đo được phải nêu rõ, không thay bằng số giả định.

### 2. Identity và UI

Login/allowlist, client registration, token, provider/model authorization; encrypt/local-save envelope, revoke và rotation. Hoàn thành khi cả confidential/public client flows được kiểm chứng theo lựa chọn đã chốt, UI/export không lộ secret và cross-user credential bị từ chối.

### 3. Gateway và Adapter

Streaming với requestId/sequence, cancellation, lỗi giữa stream, reconnect/retry tại client; models/chat completions, text/tool calls/usage. Hoàn thành khi ứng dụng thật nhận stream/tool calls đúng và báo rõ mọi kết nối bị ngắt.

### 4. Hardening và đóng gói

Test token sai/hết hạn, sai issuer/audience, đổi user/project, envelope tamper/expired/revoked, provider/model bị cấm, upstream 429, disconnect, cancel races, client chậm và resource limits. Kiểm tra credential không rò qua log/URL/UI/export; xác nhận raw prompt/response không được lưu mặc định.

Tạo GitHub template, setup idempotent, hướng dẫn/skill setup và staging deploy trước production. OAuth provider chỉ làm sau integration eligibility gate.

## Nghiệm thu tổng thể

- Ứng dụng gọi local API nhận stream và tool calls đúng.
- Ngắt kết nối/lỗi giữa stream được báo rõ; retry không trộn attempt.
- User/project không dùng được credential của nhau; revoke/tamper/token expiry thực thi đúng policy.
- Secrets không xuất hiện trong logs, URLs, UI/config export hoặc Git.
- Có kết quả benchmark thật trên Workers Free và mô tả giới hạn quan sát.

## Quyết định và gate còn mở

Stack, thư viện, envelope và WebSocket contract đã được chốt tại [ADR 0001](decisions/0001-phase-1-contracts.md); mã nguồn và staging đã có. Đọc [IMPLEMENTATION-STATUS](IMPLEMENTATION-STATUS.md) để phân biệt phần đã kiểm chứng với các gate chưa đạt.

Còn cần cấu hình OIDC application/provider và bootstrap admin thực, API key/model provider thực, xác minh Workers Free, benchmark 1/5/10 trên một socket, kiểm tra ứng dụng OpenCode/browser thật và aggregate usage/error telemetry. OAuth provider vẫn tắt theo điều kiện tích hợp. Production chưa triển khai. Domain/account/bindings staging đã được ghi trong cấu hình và tài liệu vận hành; khi dùng template ở account khác phải tạo resource và thay binding tương ứng.

## Nguồn cần đối chiếu khi triển khai

- Native OAuth: https://www.rfc-editor.org/rfc/rfc8252
- Web Crypto: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Worker Secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- OpenAI eligibility: https://developers.openai.com/siwc/token-sharing-open-source
- Anthropic login: https://support.claude.com/en/articles/13189465-log-in-to-your-claude-account

Đối chiếu nguồn chính thức trước khi thay đổi runtime hoặc auth. Điều kiện tích hợp OAuth provider chưa được xác minh; connector OAuth vẫn tắt và các URL này không phải bằng chứng eligibility.
