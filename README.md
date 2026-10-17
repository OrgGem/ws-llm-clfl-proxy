# ws-llm-clfl-proxy

Hai Cloudflare Worker và một local adapter để ứng dụng OpenAI-compatible gọi LLM qua WebSocket có xác thực.

- **Identity & Config**: đăng nhập OIDC, allowlist, user/project/client, quyền provider/model, token ngắn hạn và credential envelope.
- **LLM Socket Gateway**: WSS có xác thực, kiểm tra quyền qua private Service Binding, upstream allowlist và streaming có ACK.
- **Local Adapter**: HTTP loopback OpenAI-compatible → WSS → SSE; chạy cùng OpenCode/ứng dụng, kể cả trong môi trường cloud của client.

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

Đã qua `npm ci` và `npm run check`: **114 test**, typecheck, build, UI syntax và hai Worker dry-run. Đã deploy [Identity/UI staging](https://ws-llm-identity-staging.rpa-money.workers.dev); Gateway là `wss://ws-llm-gateway-staging.rpa-money.workers.dev/v1/socket`. Smoke thật đã kiểm chứng token/WSS và chặn envelope bị sửa trước upstream.

Staging chưa cấu hình OIDC và API key provider. Chưa có benchmark Workers Free được chứng nhận, chưa deploy production; không coi 1/5/10 tác vụ là cam kết năng lực. Dashboard hiện chỉ có số đếm thực, chưa thu thập aggregate usage/error telemetry. Xem [bằng chứng và giới hạn triển khai](docs/IMPLEMENTATION-STATUS.md) cùng [hướng dẫn adapter](apps/adapter/README.md).

Repository: https://github.com/OrgGem/ws-llm-clfl-proxy
