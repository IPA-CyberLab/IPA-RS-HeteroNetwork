import { AttributeEditor } from "../ui.jsx";
import { Box } from "../ui.jsx";
import { Button } from "../ui.jsx";
import { ColumnLayout } from "../ui.jsx";
import { Container } from "../ui.jsx";
import { Form } from "../ui.jsx";
import { FormField } from "../ui.jsx";
import { Header } from "../ui.jsx";
import { Input } from "../ui.jsx";
import { Select } from "../ui.jsx";
import { SpaceBetween } from "../ui.jsx";
import { Toggle, TagInput } from "../ui.jsx";
import { useEffect, useMemo, useState } from "react";
import { ErrorAlert } from "../components.jsx";

const protocolOptions = [
  "any",
  "ip_in_ip",
  "tcp",
  "udp",
  "sctp",
  "icmp",
  "ipv6_encap",
  "gre",
  "esp",
  "ah",
].map((value) => ({ value, label: value.toUpperCase() }));

const actionOptions = [
  { value: "allow", label: "許可" },
  { value: "deny", label: "拒否" },
];

function clonePolicy(policy) {
  return JSON.parse(JSON.stringify(policy || {}));
}

export function AclPage({ overview, onSave, saving }) {
  const [policy, setPolicy] = useState(() => clonePolicy(overview.cluster_policy));
  const [error, setError] = useState(null);

  useEffect(() => setPolicy(clonePolicy(overview.cluster_policy)), [overview.cluster_policy]);

  const updateRule = (index, field, value) => {
    setPolicy((current) => ({
      ...current,
      acl_rules: (current.acl_rules || []).map((rule, ruleIndex) =>
        ruleIndex === index ? { ...rule, [field]: value } : rule,
      ),
    }));
  };

  const definition = useMemo(
    () => [
      {
        label: "ルールID",
        control: (rule, index) => (
          <Input
            value={rule.id || ""}
            onChange={({ detail }) => updateRule(index, "id", detail.value)}
          />
        ),
      },
      {
        label: "アクション",
        control: (rule, index) => (
          <Select
            selectedOption={
              actionOptions.find((option) => option.value === rule.action) ||
              actionOptions[0]
            }
            options={actionOptions}
            onChange={({ detail }) =>
              updateRule(index, "action", detail.selectedOption.value)
            }
          />
        ),
      },
      {
        label: "プロトコル",
        control: (rule, index) => (
          <Select
            selectedOption={
              protocolOptions.find((option) => option.value === rule.protocol) ||
              protocolOptions[0]
            }
            options={protocolOptions}
            onChange={({ detail }) =>
              updateRule(index, "protocol", detail.selectedOption.value)
            }
          />
        ),
      },
      ...[
        ["from_roles", "送信元ロール"],
        ["from_tags", "送信元タグ"],
        ["to_roles", "宛先ロール"],
        ["to_tags", "宛先タグ"],
        ["routes", "ルート (CIDR)"],
      ].map(([field, label]) => ({
        label,
        control: (rule, index) => (
          <TagInput
            values={rule[field] || []}
            ariaLabel={`${label}を追加`}
            placeholder={field === "routes" ? "例: 10.0.0.0/8" : "値を入力"}
            disabled={saving}
            onChange={(values) => updateRule(index, field, values)}
          />
        ),
      })),
    ],
    [saving],
  );

  const submit = async (event) => {
    event.preventDefault();
    setError(null);
    try {
      const saved = await onSave(policy);
      setPolicy(clonePolicy(saved?.cluster_policy || saved?.policy || saved || policy));
    } catch (saveError) {
      setError(saveError);
    }
  };

  return (
    <form onSubmit={submit}>
      <Form
        header={
          <Header
            variant="h1"
            description="直接接続、NATトラバーサル、リレーとアクセスルールを制御します。"
          >
            アクセス制御
          </Header>
        }
        actions={
          <Button variant="primary" loading={saving} formAction="submit">
            ポリシーを保存
          </Button>
        }
        errorText={error ? <ErrorAlert error={error} /> : undefined}
      >
        <SpaceBetween size="l">
          <Container
            header={
              <Header variant="h2" description="実行時の接続方針">
                ポリシー設定
              </Header>
            }
          >
            <SpaceBetween size="l">
              <ColumnLayout columns={3} variant="text-grid">
                <Toggle
                  checked={Boolean(policy.allow_ipv6_direct)}
                  onChange={({ detail }) =>
                    setPolicy((current) => ({
                      ...current,
                      allow_ipv6_direct: detail.checked,
                    }))
                  }
                >
                  IPv6直接接続を許可
                </Toggle>
                <Toggle
                  checked={Boolean(policy.allow_nat_traversal)}
                  onChange={({ detail }) =>
                    setPolicy((current) => ({
                      ...current,
                      allow_nat_traversal: detail.checked,
                    }))
                  }
                >
                  NATトラバーサルを許可
                </Toggle>
                <Toggle
                  checked={Boolean(policy.allow_relay_fallback)}
                  onChange={({ detail }) =>
                    setPolicy((current) => ({
                      ...current,
                      allow_relay_fallback: detail.checked,
                    }))
                  }
                >
                  リレーフォールバックを許可
                </Toggle>
              </ColumnLayout>
              <ColumnLayout columns={3}>
                {[
                  ["idle_timeout_seconds", "アイドルタイムアウト (秒)"],
                  ["endpoint_candidate_ttl_seconds", "エンドポイントTTL (秒)"],
                  ["path_state_ttl_seconds", "経路状態TTL (秒)"],
                ].map(([field, label]) => (
                  <FormField key={field} label={label}>
                    <Input
                      type="number"
                      value={String(policy[field] ?? "")}
                      onChange={({ detail }) =>
                        setPolicy((current) => ({
                          ...current,
                          [field]: Number(detail.value),
                        }))
                      }
                    />
                  </FormField>
                ))}
              </ColumnLayout>
            </SpaceBetween>
          </Container>

          <Container
            header={
              <Header
                variant="h2"
                description="ID、タグ、ルート、プロトコルを照合します。"
                counter={`(${(policy.acl_rules || []).length})`}
              >
                アクセスルール
              </Header>
            }
          >
            <AttributeEditor
              items={policy.acl_rules || []}
              definition={definition}
              addButtonText="ルールを追加"
              removeButtonText="削除"
              removeButtonAriaLabel={(rule) => `${rule.id || "名称未設定ルール"}を削除`}
              onAddButtonClick={() =>
                setPolicy((current) => ({
                  ...current,
                  acl_rules: [
                    ...(current.acl_rules || []),
                    {
                      id: `rule-${(current.acl_rules || []).length + 1}`,
                      action: "allow",
                      protocol: "any",
                      from_roles: [],
                      from_tags: [],
                      to_roles: [],
                      to_tags: [],
                      routes: [],
                    },
                  ],
                }))
              }
              onRemoveButtonClick={({ detail }) =>
                setPolicy((current) => ({
                  ...current,
                  acl_rules: (current.acl_rules || []).filter(
                    (_, index) => index !== detail.itemIndex,
                  ),
                }))
              }
              empty={
                <Box textAlign="center" color="text-body-secondary">
                  アクセスルールはありません。
                </Box>
              }
              gridLayout={[
                {
                  rows: [[1, 1, 1], [1, 1], [1, 1], [1]],
                  removeButton: { ownRow: true },
                },
              ]}
            />
          </Container>
        </SpaceBetween>
      </Form>
    </form>
  );
}
