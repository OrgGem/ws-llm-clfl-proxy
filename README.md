# ws-llm-clfl-proxy

Hai Cloudflare Worker và một local adapter để ứng dụng OpenAI-compatible gọi LLM qua WebSocket có xác thực.

- **Identity & Config**: OIDC login, phân quyền, quản trị, token và credential envelope.
- **LLM Socket Gateway**: WSS, kiểm tra quyền, gọi provider và truyền stream.
- **Local Adapter**: HTTP OpenAI-compatible → WSS → SSE; chạy cùng client và chỉ bind loopback.

MVP: API key được mã hoá, D1, UI đi cùng Identity; OAuth provider là phần mở rộng có điều kiện.

Đọc [hướng dẫn agent](AGENTS.md) và [kế hoạch phát triển](docs/PLAN.md).

Trạng thái: mới khởi tạo tài liệu; chưa có code chạy, benchmark hoặc deploy.

Repository: https://github.com/OrgGem/ws-llm-clfl-proxy
