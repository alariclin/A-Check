<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

<p align="center">IPレピュテーション · プロキシ診断 · ノード一括選別 — 単一ファイルのPythonチェッカー</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v4.7.0-1f883d" alt="release">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab" alt="python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-8250df" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-d7781e" alt="license">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh.md">简体中文</a> · <a href="README.zh-TW.md">繁體中文</a> · <a href="README.ru.md">Русский</a> · <a href="README.fa.md">فارسی</a>
</p>

---

## スクリーンショット

起動画面 — グラデーションロゴ + リアルタイム情報パネル + 2カラムメニュー：

![メイン画面](docs/showcase-menu.png)

レポート例：

![レポート](docs/showcase-report.png)

ノード一括速度テスト：

![一括テスト](docs/showcase-batch.png)

## 機能

- **IPレピュテーション**：複数のデータソースを並行集約（ipwho.is、ipinfo、proxycheck、Scamalytics、DB-IP、GreyNoise など）、値はすべて出典付き、スコアリングルールは完全公開（`--explain`）
- **ストリーミング解錠**：動画 / AI / ソーシャル計18項目、ネイティブ解錠とDNS解錠を区別
- **ブラックリスト**：DNSBL 29リスト + 脅威インテリジェンス照合（Feodo、Emerging Threats、Tor出口ノード）
- **プロキシ診断**：SOCKS5ハンドシェイクと遅延、プロキシ経由の出口IPとレピュテーション再確認、DNSリーク確認、TCP遅延 / ジッター / ロス統計
- **ノード一括選別**：複数のノード（`host:port` または `socks5://…`）を貼り付けて並行速度テスト、ランキング表示、最速ノードを自動マーク
- **速度テスト**：地域別ノードのダウンロード測定（bench.sh式ノード表、複数接続ピーク）；プロキシ診断と一括選別ではプロキシ経由の実スループットも測定
- **セルフチェック**：出口IP全検 + DNSテスト（平文 / DoH / DoT）+ ポート25送信テスト + システム情報とディスクIOベンチマーク
- **依存ゼロ**：純粋なPython標準ライブラリの単一ファイル、公開版はAPIキー不要；UI 6言語；`--json` 出力でスクリプト連携可能

## クイックスタート

```bash
# 単一ファイルをダウンロード
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py

# 対話メニュー（推奨）
python3 acheck.py

# コマンドライン
python3 acheck.py 8.8.8.8     # 任意のIPを照会
python3 acheck.py --active    # セルフチェック
```

macOS / Windows / Linux 用パッケージは [Releases](https://github.com/alariclin/A-Check/releases) ページ（`A-Check-v4.7.0-mac.zip` / `A-Check-v4.7.0-windows.zip` / `A-Check-v4.7.0-linux.zip`）から。解凍して `run.command` / `run.bat` / `run.sh` を実行してください。

## 使い方

| モード | コマンド | 説明 |
| --- | --- | --- |
| 対話メニュー | `python3 acheck.py` | 11機能の2カラムメニュー |
| 任意IP照会 | `python3 acheck.py 1.2.3.4` | 複数ソースのレピュテーション + ブラックリスト + 全レポート |
| セルフチェック | `python3 acheck.py --active` | 出口確認 + ストリーミング + システム情報 |
| プロキシ診断 | `python3 acheck.py --proxy HOST:PORT` | ハンドシェイク / 出口 / DNSリーク / 遅延（`--proxy-user`、`--proxy-pass` で認証） |
| 一括選別 | `python3 acheck.py --batch ノード,ノード…` | 並行速度テストとランキング |
| 速度テスト | `python3 acheck.py --speed` | 地域別ダウンロード測定 |
| JSON出力 | 各モードに `--json` を追加 | スクリプト / 通知 / 連携用 |
| スコアリングルール | `python3 acheck.py --explain` | 3次元スコアリングルール全文 |
| 言語 | `--zh` / `--zh-tw` / `--en` / `--ja` / `--ru` / `--fa` | メニュー内でも切替可能 |

## 注意事項

- **プライバシー**：すべての確認はローカルで実行され、ユーザーデータを外部に送信しません；公開版にAPIキーは含まれません
- **レート制限**：各データソースには無料枠があります。短時間に大量の照会を行うと制限される場合があり、欠けたソースはレポートに明記されます
- **結果**：スコアは公開情報の集約です。ソース間で結論が異なる場合があり、レポートには項目ごとに出典を明記します。参考用です
- **互換性**：Python 3.8+ が必要です；macOS / Windows / Linux / VPS で動作します

---

変更履歴は [Releases](https://github.com/alariclin/A-Check/releases) · MIT License · データソースはレポート内に項目ごとに明記
