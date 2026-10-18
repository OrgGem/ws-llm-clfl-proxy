# ws-llm-clfl-proxy

Hai Cloudflare Worker và một local adapter để ứng dụng OpenAI-compatible gọi LLM qua WebSocket có xác thực.

- **Identity & Config**: đăng nhập OIDC, allowlist, user/project/client, quyền provider/model, token ngắn hạn và credential envelope.
- **LLM Socket Gateway**: WSS có xác thực, kiểm tra quyền qua private Service Binding, upstream allowlist và streaming có ACK.
- **Local Adapter 0.5.0**: CLI và HTTP loopback OpenAI-compatible → WSS → SSE; hỗ trợ Chat Completions, Responses và legacy Completions, cả stream và JSON; có chế độ request qua môi trường dành cho agent.

MVP dùng API key mã hoá AES-256-GCM; D1 giữ metadata/trạng thái revoke. OAuth ChatGPT được quản lý tại local adapter, với UI cloud điều khiển qua bridge ghép nối có xác nhận; cloud inference vẫn tắt đến khi xác minh điều kiện tích hợp. OAuth Claude chưa được hỗ trợ. Login OIDC của hệ thống không cấp quyền dùng subscription LLM. Xem [hướng dẫn OAuth](docs/OAUTH.md).

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
- [Hướng dẫn agent client và CLI](docs/AGENT-CLIENT.md) · [Template có thể sao chép](templates/ws-llm-agent/README.md) · [Skill dùng CLI](.agents/skills/ws-llm-cli/SKILL.md)

Kết quả kiểm thử hiện tại và giới hạn bằng chứng được ghi tại [Implementation Status](docs/IMPLEMENTATION-STATUS.md). UI staging tại https://llm.gemslab.id.vn/ui; Gateway là `wss://llm.gemslab.id.vn/v1/socket`.

Staging có cấu hình OIDC, provider custom và credential do người dùng thiết lập; đã kiểm thử thật OpenCode Go với JSON, SSE và tool calls; OAuth ChatGPT chưa được kiểm chứng bằng đăng nhập thật. Chưa có benchmark Workers Free được chứng nhận, chưa deploy production riêng; không coi 1/5/10 tác vụ là cam kết năng lực. Dashboard hiện chỉ có số đếm thực, chưa thu thập aggregate usage/error telemetry. Responses là generation stateless, không gồm stored-response/conversation APIs; provider phải hỗ trợ endpoint native được chọn. Xem [bằng chứng và giới hạn triển khai](docs/IMPLEMENTATION-STATUS.md) cùng [hướng dẫn adapter](apps/adapter/README.md).

Repository: https://github.com/OrgGem/ws-llm-clfl-proxy
