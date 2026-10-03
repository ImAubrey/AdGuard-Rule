# AdGuard Rule

一个 Go 编写的 AdGuard / AdGuard Home 规则合并器：定时读取远程和本地规则，去重后按类型输出 TXT，同时生成 Xray 可加载的 `geosite.dat` 和 `geoip.dat`。

## 输出文件

- `all.txt`：DOMAIN、HOSTS、REGEX、MODIFY 的完整文本合集。
- `adgh.txt`：适用于 AdGuard Home 的 DOMAIN 和 REGEX 规则。
- `domain.txt`、`hosts.txt`、`regex.txt`、`modify.txt`：按类型拆分的文本规则。
- `geosite.dat`：Xray/V2Ray GeoSite protobuf 文件。
- `geoip.dat`：从规则中的 IP/CIDR 提取的 Xray/V2Ray GeoIP protobuf 文件。

`geosite.dat` 包含以下标签：

- `ADGUARD-ALL`：尽可能转换的全部域名规则。
- `ADGUARD-BLOCK`：不以 `@@` 开头的规则，适合拦截路由。
- `ADGUARD-ALLOW`：以 `@@` 开头的例外规则。
- `ADGUARD-DOMAIN`、`ADGUARD-REGEX`、`ADGUARD-MODIFY`：按来源类型拆分。
- `SCRIPT`、`THIRD-PARTY`：从 AdGuard 的 `$script`、`$third-party` 等选项生成的类别。
- `ALLOW`：所有以 `@@` 开头的例外规则，别名为 `geosite:allow`。

AdGuard 的修饰符无法全部一一映射到 Xray，程序会尽量提取域名或转换为正则；无法安全转换的规则只保留在 TXT 中。

Xray 配置示例：

```json
{
  "domain": [
    "ext:geosite.dat:ADGUARD-BLOCK",
    "ext:geosite.dat:script",
    "ext:geosite.dat:third-party",
    "ext:geosite.dat:allow"
  ],
  "ip": ["ext:geoip.dat:ADGUARD"]
}
```

将两个 `.dat` 文件放入 Xray 的资源目录。若把生成的 `geosite.dat` 作为默认 GeoSite 文件，也可以直接使用 `geosite:script`、`geosite:third-party`、`geosite:allow`。Xray 不会像 AdGuard 那样自动执行例外优先级。

## 使用

需要 Go 1.25.5 或更高版本：

```bash
go mod download
go run . -config config.yaml
```

也可以构建可执行文件：

```bash
go build -trimpath -o adguardhome-rule-gen .
./adguardhome-rule-gen -config config.yaml
```

默认配置文件是根目录的 `config.yaml`。远程规则放在 `application.rule.remote`，本地规则文件放在 `rule` 目录，输出设置在 `application.output`，Xray 输出设置在 `application.xray`。

## GitHub Actions

项目内的 `main.yml` 和 `auto-update.yml` 会使用 Go 构建并执行程序，然后提交生成的规则文件。默认每 12 小时运行一次。
