# AWS Security Snapshot

AWS CLI の既存認証を使って、AWSアカウントの代表的なセキュリティ設定を**読み取り専用**で棚卸しする小さなCLIです。

このリポジトリは公開を前提にしています。ツールは認証情報を保存せず、レポートにはAWSアカウントIDを下4桁以外マスクし、S3バケット名などのリソース名も出力しません。

## チェック内容

- RootユーザーのMFA
- Rootユーザーのアクセスキー有無
- S3 Block Public Access
- S3 Versioning
- CloudTrailの記録状態
- CloudTrailのマルチリージョン化
- CloudTrailログファイル検証
- CloudTrailのKMS暗号化
- GuardDuty
- AWS Config
- Security Hub
- EBSデフォルト暗号化

## 必要なもの

- Python 3.11+
- AWS CLI v2
- 読み取り権限を持つAWS CLIプロファイルまたはその他のAWS CLI認証

長期アクセスキーをこのリポジトリに置く必要はありません。AWS IAM Identity Center / SSO や短期クレデンシャルの利用を推奨します。

## 実行例

東京リージョンを確認:

```bash
python3 src/aws_security_snapshot.py --profile my-sso --region ap-northeast-1
```

有効な全リージョンを確認し、ローカルファイルに保存:

```bash
python3 src/aws_security_snapshot.py \
  --profile my-sso \
  --all-regions \
  --output reports/security-snapshot.md
```

JSON出力:

```bash
python3 src/aws_security_snapshot.py \
  --profile my-sso \
  --region ap-northeast-1 \
  --format json
```

高重要度のFAIL/ERRORがあれば終了コード2にする:

```bash
python3 src/aws_security_snapshot.py \
  --profile my-sso \
  --region ap-northeast-1 \
  --fail-on high
```

## 権限について

このCLIが呼び出すのは参照系APIのみです。典型的には次のような権限が必要です。

- `sts:GetCallerIdentity`
- `iam:GetAccountSummary`
- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketVersioning`
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `guardduty:ListDetectors`
- `guardduty:GetDetector`
- `config:DescribeConfigurationRecorders`
- `config:DescribeConfigurationRecorderStatus`
- `securityhub:DescribeHub`
- `ec2:GetEbsEncryptionByDefault`
- `ec2:DescribeRegions`（`--all-regions` 使用時）

既存のReadOnlyAccess相当でも実行できますが、本番環境では必要最小限の監査用ロールを作る方が安全です。

## 出力の扱い

`reports/`、`*.audit.json`、`*.audit.md` は `.gitignore` 済みです。

ただし、監査結果には環境のセキュリティ状態そのものが含まれます。**生成したレポートを公開リポジトリへコミットしないでください。**

## テスト

外部パッケージなしで実行できます。

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## 設計方針

- AWS環境を変更しない
- 秘密情報をリポジトリに保存しない
- リソース名をレポートに含めない
- アカウントIDをマスクする
- AWS SDK依存を増やさず、既存のAWS CLI認証をそのまま使う
- API呼び出しに失敗した場合は、問題なしと誤認せず `ERROR` として扱う

> このツールは簡易的なスナップショットです。AWS Security Hub、AWS Config、CSPM製品、正式なセキュリティレビューの代替ではありません。
