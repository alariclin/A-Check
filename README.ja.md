<p align="center">
  <img width="441" height="450" src="icon.webp" alt="IPCheck">
</p>

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

IPCheck はデュアルモード IP レピュテーションチェッカーです：自端末の出口 IP を自己診断 / 任意のパブリック IP を照会。Python 標準ライブラリのみ、依存関係ゼロ、すぐに使えます。

## 特徴

- **16 の無料データソース**、API キー不要、オープンソースで無料
- **デュアルモード**：
  - `[1]` 自己診断 — 現在のデバイスの出口 IP を検査。ストリーミングのアクティブなアンロックテスト、DNS フルテスト、25 番ポート送信テスト、61 の DNSBL ブラックリスト、Cloudflare 速度測定を含む
  - `[2]` IP 照会 — 任意のパブリック IP を入力し、公開インテリジェンスのパッシブ照会のみ実行。ストリーミング利用可否のシミュレーション推測と DNS 推奨付き
- **6 言語 UI**：简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **リスクスコア 0–100** + カラープログレスバー
- **ストリーミングアンロック検出**：ネイティブアンロック / DNS アンロックを区別
- **25 番ポート送信テスト** + 61 の DNSBL ブラックリスト（20 スレッド並行、数十秒で完了）
- **システム情報**：CPU / メモリ / ディスク / 仮想化 + ディスク I/O ベンチマーク
- **Cloudflare 速度測定**（参考用）
- **DNS フルテスト**：従来 DNS（UDP 53）/ DoH / DoT
- **クロスプラットフォーム**：macOS / Windows / Linux

## クイックスタート

```bash
# VPS / Linux / macOS ワンライナー（Python 3.8+ が必要）
curl -sL https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -o ipcheck.py && python3 ipcheck.py

# Windows PowerShell one-liner (requires Python 3.8+)
irm https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -OutFile ipcheck.py; python ipcheck.py
```

サードパーティ依存関係なし — Python 標準ライブラリのみ使用。

## モード説明

### [1] 自己診断

現在のデバイスの出口 IP を検査します：

1. パッシブ IP プロファイリング（ASN / BGP / 位置情報 / IP タイプ）
2. 脅威インテリジェンス（16 ソース集約）
3. 不正スコアとリスク要因マトリックス
4. システム情報（CPU / メモリ / ディスク / 仮想化 / ディスク I/O）
5. ストリーミングのアクティブテスト（TikTok / Netflix / Disney+ / YouTube / ChatGPT など、ネイティブ / DNS アンロック区別）
6. DNS フルテスト（従来 / DoH / DoT）
7. 25 番ポート送信テスト + DNSBL ブラックリスト
8. Cloudflare 速度測定

### [2] IP 照会

任意のパブリック IP を入力し、公開インテリジェンスのパッシブ照会のみ実行：

- マルチソース IP プロファイリングと位置比較
- 脅威インテリジェンスとリスクスコア
- ストリーミング利用可否の**シミュレーション推測**（⚠️ 実際の接続テストではありません、参考用）
- IP の国/地域に基づく DNS 推奨と、利用不可と判明している項目の一覧

## データソース（16 の無料ソース）

| カテゴリ | ソース |
|----------|--------|
| IP プロファイリング | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI |
| 脅威インテリジェンス | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, EmergingThreats, Tor Exit Nodes |
| ネットワーク | RIPEstat（ASN/BGP）、PTR（逆引き）、Shodan InternetDB |
| ブラックリスト | DNSBL（61 の公開ブラックリスト） |


## 類似ツールとの比較

| 機能 | IPCheck | xykt/IPQuality | ip-check-tool |
|------|---------|----------------|---------------|
| UI 言語 | 6 言語 | 中 / 英 | 中 / 英 |
| Windows 対応 | ✅ | ⚠️ 部分的 | ⚠️ 部分的 |
| DNSBL 検査 | ✅ 61 件（並行） | ❌ | ⚠️ 少数 |
| ストリーミングアンロック種別（ネイティブ/DNS） | ✅ | ✅ | ⚠️ |
| システム情報 + ディスク I/O | ✅ | ❌ | ❌ |
| DNS フル対応（DoH/DoT） | ✅ | ⚠️ | ❌ |
| 依存関係ゼロ（標準ライブラリのみ） | ✅ | ❌ | ❌ |
| ライセンス | MIT | AGPL-3.0 | MIT |

## スクリーンショット

（プレースホルダー：モード1 / モード2 / リスクスコア / ストリーミングテスト）

## ライセンス

MIT License — [LICENSE](LICENSE) を参照。

## 免責事項

- 学習・研究目的でのみ使用してください。
- すべてのデータは公開インテリジェンスソースの集約であり、パッシブ照会の結果はリアルタイムの正確性を保証しません。「証拠なし ≠ リスクなし」。
- ストリーミングのシミュレーション推測は実際の接続テストではありません。参考用です。
- 現地の法令および各データソースの利用規約を遵守し、攻撃・悪用・違法目的に使用しないでください。
