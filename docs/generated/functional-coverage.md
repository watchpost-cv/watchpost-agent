# watchpost-agent functional coverage

Generated from the tested operation manifest. Do not edit by hand.

| Operation | Website | API | CLI | Permission | Schemas | Tests |
| --- | :---: | --- | --- | --- | --- | --- |
| `watchpost-agent.accounts.create` | yes | `POST /api/v1/accounts` | `accounts create` | `capability:watchpost-agent.role.admin` | `watchpost-agent.accounts.create.request.v1 → watchpost-agent.accounts.create.response.v1` | internal/app/app_test.go |
| `watchpost-agent.accounts.list` | yes | `GET /api/v1/accounts` | `accounts list` | `capability:watchpost-agent.role.admin` | `— → watchpost-agent.accounts.list.response.v1` | internal/app/app_test.go |
| `watchpost-agent.accounts.revoke-sessions` | yes | `POST /api/v1/accounts/{id}/revoke-sessions` | `accounts revoke-sessions` | `capability:watchpost-agent.role.admin` | `watchpost-agent.accounts.revoke-sessions.request.v1 → watchpost-agent.accounts.revoke-sessions.response.v1` | internal/app/app_test.go |
| `watchpost-agent.agent.reset` | yes | `POST /api/v1/reset` | `agent reset` | `capability:watchpost-agent.role.admin` | `watchpost-agent.agent.reset.request.v1 → watchpost-agent.agent.reset.response.v1` | internal/app/app_test.go |
| `watchpost-agent.audit.list` | yes | `GET /api/v1/audit` | `audit list` | `capability:watchpost-agent.role.admin` | `— → watchpost-agent.audit.list.response.v1` | internal/app/app_test.go |
| `watchpost-agent.auth.bootstrap` | yes | `GET /api/v1/bootstrap` | `auth bootstrap` | `public` | `— → watchpost-agent.auth.bootstrap.response.v1` | internal/app/app_test.go |
| `watchpost-agent.auth.login` | yes | `POST /api/v1/login` | `auth login` | `public` | `watchpost-agent.auth.login.request.v1 → watchpost-agent.auth.login.response.v1` | internal/app/app_test.go |
| `watchpost-agent.auth.logout` | yes | `POST /api/v1/logout` | `auth logout` | `capability:watchpost-agent.role.viewer` | `watchpost-agent.auth.logout.request.v1 → watchpost-agent.auth.logout.response.v1` | internal/app/app_test.go |
| `watchpost-agent.auth.password.update` | yes | `POST /api/v1/me/password` | `auth-password update` | `capability:watchpost-agent.role.viewer` | `watchpost-agent.auth.password.update.request.v1 → watchpost-agent.auth.password.update.response.v1` | internal/app/app_test.go |
| `watchpost-agent.auth.setup` | yes | `POST /api/v1/setup` | `auth setup` | `public` | `watchpost-agent.auth.setup.request.v1 → watchpost-agent.auth.setup.response.v1` | internal/app/app_test.go |
| `watchpost-agent.collectors.list` | yes | `GET /api/v1/collectors` | `collectors list` | `capability:watchpost-agent.role.viewer` | `— → watchpost-agent.collectors.list.response.v1` | internal/app/app_test.go |
| `watchpost-agent.collectors.update` | yes | `PUT /api/v1/collectors` | `collectors update` | `capability:watchpost-agent.role.technician` | `watchpost-agent.collectors.update.request.v1 → watchpost-agent.collectors.update.response.v1` | internal/app/app_test.go |
| `watchpost-agent.connection.rotate` | yes | `POST /api/v1/rotate` | `connection rotate` | `capability:watchpost-agent.role.admin` | `watchpost-agent.connection.rotate.request.v1 → watchpost-agent.connection.rotate.response.v1` | internal/app/app_test.go |
| `watchpost-agent.connection.unpair` | yes | `POST /api/v1/unpair` | `connection unpair` | `capability:watchpost-agent.role.admin` | `watchpost-agent.connection.unpair.request.v1 → watchpost-agent.connection.unpair.response.v1` | internal/app/app_test.go |
| `watchpost-agent.health.get` | no | `GET /healthz` | `health get` | `public` | `— → watchpost-agent.health.get.response.v1` | internal/app/app_test.go |
| `watchpost-agent.launcher.config.update` | yes | `PUT /api/launcher/config` | `launcher-config update` | `capability:watchpost-agent.role.admin` | `watchpost-agent.launcher.config.update.request.v1 → watchpost-agent.launcher.config.update.response.v1` | internal/app/app_test.go |
| `watchpost-agent.launcher.instances.list` | yes | `GET /api/launcher/instances` | `launcher-instances list` | `public` | `— → watchpost-agent.launcher.instances.list.response.v1` | internal/app/app_test.go |
| `watchpost-agent.pairing.poll` | yes | `POST /api/v1/pairing/poll` | `pairing poll` | `capability:watchpost-agent.role.technician` | `watchpost-agent.pairing.poll.request.v1 → watchpost-agent.pairing.poll.response.v1` | internal/app/app_test.go |
| `watchpost-agent.pairing.request` | yes | `POST /api/v1/pairing/request` | `pairing request` | `capability:watchpost-agent.role.technician` | `watchpost-agent.pairing.request.request.v1 → watchpost-agent.pairing.request.response.v1` | internal/app/app_test.go |
| `watchpost-agent.ready.get` | no | `GET /readyz` | `ready get` | `public` | `— → watchpost-agent.ready.get.response.v1` | internal/app/app_test.go |
| `watchpost-agent.status.get` | yes | `GET /api/v1/status` | `status get` | `capability:watchpost-agent.role.viewer` | `— → watchpost-agent.status.get.response.v1` | internal/app/app_test.go |
