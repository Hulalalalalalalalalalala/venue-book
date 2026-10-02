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
- 未知路径返回 404，已知路径不支持的方法返回 405。

```sh
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/api/venues
```
