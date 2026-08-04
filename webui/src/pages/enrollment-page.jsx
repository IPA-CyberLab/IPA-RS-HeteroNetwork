import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Container from "@cloudscape-design/components/container";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import Form from "@cloudscape-design/components/form";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import Select from "@cloudscape-design/components/select";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Toggle from "@cloudscape-design/components/toggle";
import { useEffect, useState } from "react";
import { Empty, ErrorAlert } from "../components.jsx";
import { copyText, csvValues, formatDateTime } from "../utils.js";

const roleOptions = [
  { value: "edge", label: "エッジ" },
  { value: "worker", label: "ワーカー" },
  { value: "gateway", label: "ゲートウェイ" },
];

function Result({ mode, result, onReset, onNotify }) {
  if (!result) return null;
  const primaryValue =
    mode === "desktop" ? result.enrollment_uri : result.install_command;
  const copy = async (value, label) => {
    try {
      await copyText(value);
      onNotify(`${label}をコピーしました。`, "success");
    } catch (error) {
      onNotify(error.message, "error");
    }
  };
  const download = () => {
    const url = URL.createObjectURL(
      new Blob([result.install_script], {
        type: "text/x-shellscript;charset=utf-8",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "install-heteronetwork.sh";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Container
      header={
        <Header
          variant="h2"
          description={
            mode === "desktop"
              ? "HeteroNetworkアプリをインストールした端末で開きます。"
              : "sudoを利用できるユーザーとして対象Linuxサーバーで実行します。"
          }
          actions={<Button onClick={onReset}>別の認証情報を作成</Button>}
        >
          {mode === "desktop" ? "登録リンク" : "インストールコマンド"}
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Alert type="warning" header="秘密情報です">
          登録が完了するまで第三者へ共有しないでください。ブラウザーには保存されません。
        </Alert>
        <div className="command-output">
          <Box variant="pre">{primaryValue}</Box>
          <Button
            iconName="copy"
            ariaLabel="コピー"
            onClick={() =>
              copy(primaryValue, mode === "desktop" ? "リンク" : "コマンド")
            }
          />
        </div>
        <KeyValuePairs
          columns={3}
          items={[
            { label: "有効期限", value: formatDateTime(result.expires_at) },
            { label: "最大利用回数", value: mode === "desktop" ? "1" : String(result.max_uses || 1) },
            { label: "対象", value: mode === "desktop" ? "macOS / Windows" : result.architecture || "linux-amd64" },
          ]}
        />
        <SpaceBetween direction="horizontal" size="xs">
          {mode === "desktop" ? (
            <Button variant="primary" iconName="external" href={result.enrollment_uri}>
              HeteroNetworkで開く
            </Button>
          ) : (
            <Button variant="primary" iconName="download" onClick={download}>
              スクリプトをダウンロード
            </Button>
          )}
          <Button iconName="copy" onClick={() => copy(primaryValue, "認証情報")}>
            コピー
          </Button>
        </SpaceBetween>
        <ExpandableSection headerText="登録トークン">
          <SpaceBetween size="s">
            <Box variant="pre">{JSON.stringify(result.token, null, 2)}</Box>
            <Button
              iconName="copy"
              onClick={() => copy(JSON.stringify(result.token), "トークン")}
            >
              トークンをコピー
            </Button>
          </SpaceBetween>
        </ExpandableSection>
      </SpaceBetween>
    </Container>
  );
}

export function EnrollmentPage({ config, onIssue, issuing, onNotify }) {
  const availableModes = [];
  if (config?.node_enrollment_enabled) {
    availableModes.push({ id: "linux", text: "Linuxノード", iconName: "script" });
  }
  if (config?.client_enrollment_enabled) {
    availableModes.push({ id: "desktop", text: "デスクトップ", iconName: "user-profile" });
  }
  const [mode, setMode] = useState(availableModes[0]?.id || "linux");
  const [role, setRole] = useState(roleOptions[0]);
  const [tags, setTags] = useState("");
  const [reusable, setReusable] = useState(false);
  const [expirationDays, setExpirationDays] = useState("7");
  const [maxUses, setMaxUses] = useState("10");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!availableModes.some((entry) => entry.id === mode)) {
      setMode(availableModes[0]?.id || "linux");
    }
  }, [config, mode]);

  if (!availableModes.length) {
    return (
      <Empty
        title="ノード登録が無効です"
        description="コントロールプレーンで登録機能を有効にしてください。"
      />
    );
  }

  const submit = async (event) => {
    event.preventDefault();
    setError(null);
    const days = Math.floor(Number(expirationDays));
    const uses = Math.floor(Number(maxUses));
    if (!Number.isFinite(days) || days < 1 || days > 30) {
      setError(new Error("有効期限は1日から30日の範囲で指定してください。"));
      return;
    }
    if (mode === "linux" && reusable && (!Number.isFinite(uses) || uses < 2 || uses > 1000)) {
      setError(new Error("最大利用回数は2回から1000回の範囲で指定してください。"));
      return;
    }
    try {
      const body =
        mode === "desktop"
          ? { expires_in_seconds: days * 86400 }
          : {
              expires_in_seconds: days * 86400,
              role: role.value,
              tags: csvValues(tags),
              reusable,
              max_uses: reusable ? uses : 1,
            };
      const issued = await onIssue(mode, body);
      setResult(issued);
      onNotify("登録認証情報を発行しました。", "success");
    } catch (issueError) {
      setError(issueError);
    }
  };

  return (
    <SpaceBetween size="l">
      <Header
        variant="h1"
        description="短期認証情報を発行し、新しい実マシンまたはデスクトップを参加させます。"
      >
        ノードを追加
      </Header>
      <SegmentedControl
        selectedId={mode}
        options={availableModes}
        onChange={({ detail }) => {
          setMode(detail.selectedId);
          setResult(null);
          setError(null);
        }}
        label="登録する端末の種類"
      />
      <form onSubmit={submit}>
        <Form
          actions={
            <Button variant="primary" loading={issuing} formAction="submit">
              {mode === "desktop" ? "登録リンクを生成" : "インストールコマンドを生成"}
            </Button>
          }
          errorText={error ? <ErrorAlert error={error} /> : undefined}
        >
          <Container
            header={
              <Header variant="h2">
                {mode === "desktop" ? "デスクトップ登録設定" : "Linuxノード設定"}
              </Header>
            }
          >
            <SpaceBetween size="l">
              {mode === "linux" ? (
                <ColumnLayout columns={2}>
                  <FormField label="ノードロール">
                    <Select
                      selectedOption={role}
                      options={roleOptions}
                      onChange={({ detail }) => setRole(detail.selectedOption)}
                    />
                  </FormField>
                  <FormField label="タグ" description="カンマ区切り">
                    <Input
                      value={tags}
                      placeholder="production, linux"
                      onChange={({ detail }) => setTags(detail.value)}
                    />
                  </FormField>
                </ColumnLayout>
              ) : (
                <Alert type="info">
                  単回利用の登録リンクです。デスクトップクライアントはルート広報やリレーを行いません。
                </Alert>
              )}
              <ColumnLayout columns={2}>
                <FormField label="有効期限 (日)">
                  <Input
                    type="number"
                    value={expirationDays}
                    onChange={({ detail }) => setExpirationDays(detail.value)}
                  />
                </FormField>
                {mode === "linux" ? (
                  <SpaceBetween size="s">
                    <Toggle
                      checked={reusable}
                      onChange={({ detail }) => setReusable(detail.checked)}
                    >
                      複数ノードで再利用する
                    </Toggle>
                    {reusable ? (
                      <FormField label="最大利用回数">
                        <Input
                          type="number"
                          value={maxUses}
                          onChange={({ detail }) => setMaxUses(detail.value)}
                        />
                      </FormField>
                    ) : null}
                  </SpaceBetween>
                ) : null}
              </ColumnLayout>
            </SpaceBetween>
          </Container>
        </Form>
      </form>
      <Result
        mode={mode}
        result={result}
        onReset={() => setResult(null)}
        onNotify={onNotify}
      />
    </SpaceBetween>
  );
}
