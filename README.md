# ws-llm-clfl-proxy

Hai Cloudflare Worker và một local adapter để ứng dụng OpenAI-compatible gọi LLM qua WebSocket có xác thực.

- **Identity & Config**: đăng nhập OIDC, allowlist, user/project/client, quyền provider/model, token ngắn hạn và credential envelope.
- **LLM Socket Gateway**: WSS có xác thực, kiểm tra quyền qua private Service Binding, upstream allowlist và streaming có ACK.
- **Local Adapter 0.3.0**: HTTP loopback OpenAI-compatible → WSS → SSE; hỗ trợ Chat Completions, Responses và legacy Completions, cả stream và JSON; chạy cùng OpenCode/ứng dụng, kể cả trong môi trường cloud của client.

MVP dùng API key mã hoá AES-256-GCM; D1 giữ metadata/trạng thái revoke. OAuth provider vẫn tắt đến khi xác minh điều kiện tích hợp. Login OIDC của hệ thống không cấp quyền dùng subscription LLM.

## Phát triển local

Yêu cầu Node.js 24 và npm. Bộ test TLS dùng OpenSSL để tạo certificate tạm; gói CLI chạy cùng client không cần OpenSSL. Từ thư mục repo:

```sh
npm ci
node scripts/setup-local.mjs
npm run check
```

Script setup tạo khoá phát triển vào file được Git bỏ qua, quyền owner-only; chạy lại giữ nguyên cấu hình cũ. Không dùng khoá local cho staging/production. Cần cấu hình OIDC và bootstrap admin trước khi đăng nhập. Không gửi secrets qua chat, commit hoặc tham số dòng lệnh.

Hướng dẫn cấu hình/deploy và giới hạn bằng chứng: [OPERATIONS](docs/OPERATIONS.md).

## Tài liệu

- [Hướng dẫn agent](AGENTS.md)
- [Kế hoạch và tiêu chí nghiệm thu](docs/PLAN.md)
- [ADR: contract triển khai](docs/decisions/0001-phase-1-contracts.md)
- [WebSocket protocol v1](docs/PROTOCOL.md)
- [Threat model](docs/THREAT-MODEL.md)

Đã qua `npm run check`: **215 test**, typecheck, build, UI syntax và hai Worker dry-run. UI staging tại https://llm.gemslab.id.vn/ui; Gateway là `wss://llm.gemslab.id.vn/v1/socket`. Smoke thật kiểm chứng token/WSS, API selection, stateless policy và chặn envelope bị sửa trước upstream. OpenAI SDK 7.38.0 đã được kiểm tra với HTTP/SSE fixture local.

Staging có cấu hình OIDC, provider custom và credential do người dùng thiết lập; kiểm thử hiện tại không gọi provider thật. Chưa có benchmark Workers Free được chứng nhận, chưa deploy production riêng; không coi 1/5/10 tác vụ là cam kết năng lực. Dashboard hiện chỉ có số đếm thực, chưa thu thập aggregate usage/error telemetry. Responses là generation stateless, không gồm stored-response/conversation APIs; provider phải hỗ trợ endpoint native được chọn. Xem [bằng chứng và giới hạn triển khai](docs/IMPLEMENTATION-STATUS.md) cùng [hướng dẫn adapter](apps/adapter/README.md).

Repository: https://github.com/OrgGem/ws-llm-clfl-proxy
