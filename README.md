# VenueBook

场地预约与活动报名。

需要Go 1.22 或更新版本。

查看命令帮助：

```sh
go run . --help
```

启动本地服务：

```sh
go run . serve --host 127.0.0.1 --port 8080 --data-dir data
```

打开 http://127.0.0.1:8080 查看首页。Ctrl+C 停止服务。`--data-dir` 指定本地业务数据目录，重启时继续使用同一目录。

接口：

- `GET /health` 返回服务状态和产品名称。
- `GET /api/venues` 返回场地列表，首次启动时为空。
- `POST /api/venues` 新增场地，请求体为 JSON 对象，包含：
  - `name`：名称，去除首尾空白后不能为空。
  - `capacity`：正整数容量。
  - `timezone`：有效的 IANA 时区名称，例如 `Asia/Shanghai`。
  - `weeklyHours`：每周开放时间数组，允许为空；每项包含 `weekday`（1 至 7，周一至周日）、`start`、`end`（严格 `HH:mm`，00:00 至 23:59）。结束时间早于开始时间表示次日结束；各时段不得相交或互相包含（首尾相接可以保存）。
- 未知路径返回 404，已知路径不支持的方法返回 405（`Allow` 反映该路径支持的方法）。

保存失败时返回 400（校验错误，`error` 字段说明原因）或 500（数据读取或保存失败），不会写入部分记录。

```sh
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/api/venues
curl -X POST http://127.0.0.1:8080/api/venues -H 'Content-Type: application/json' \
  -d '{"name":"主楼报告厅","capacity":200,"timezone":"Asia/Shanghai","weeklyHours":[{"weekday":1,"start":"09:00","end":"17:00"}]}'
```
