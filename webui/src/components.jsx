import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Header from "@cloudscape-design/components/header";
import Pagination from "@cloudscape-design/components/pagination";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Spinner from "@cloudscape-design/components/spinner";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Table from "@cloudscape-design/components/table";
import TextFilter from "@cloudscape-design/components/text-filter";
import { useCollection } from "@cloudscape-design/collection-hooks";
import { useEffect, useId, useMemo, useState } from "react";
import { statusType } from "./utils.js";

export function Status({ value, children }) {
  return (
    <StatusIndicator type={statusType(value)}>
      {children ?? value ?? "不明"}
    </StatusIndicator>
  );
}

export function Empty({ title, description, action }) {
  return (
    <Box margin={{ vertical: "xxl" }} textAlign="center" color="inherit">
      <SpaceBetween size="m">
        <div>
          <Box variant="strong">{title}</Box>
          {description ? (
            <Box variant="p" color="text-body-secondary">
              {description}
            </Box>
          ) : null}
        </div>
        {action}
      </SpaceBetween>
    </Box>
  );
}

export function ResourceTable({
  items,
  columns,
  trackBy,
  header,
  description,
  actions,
  searchPlaceholder = "検索",
  searchText = (item) => JSON.stringify(item),
  emptyTitle = "リソースがありません",
  emptyDescription,
  pageSize = 10,
  onRowClick,
  stickyHeader = true,
}) {
  const { collectionProps, filterProps, paginationProps, filteredItemsCount, items: pageItems } =
    useCollection(items, {
      filtering: {
        filteringFunction: (item, filteringText) =>
          searchText(item).toLowerCase().includes(filteringText.toLowerCase()),
        empty: <Empty title={emptyTitle} description={emptyDescription} />,
        noMatch: (
          <Empty
            title="一致するリソースがありません"
            description="検索条件を変更してください。"
          />
        ),
      },
      sorting: {},
      pagination: { pageSize },
    });

  return (
    <Table
      {...collectionProps}
      variant="container"
      stickyHeader={stickyHeader}
      stripedRows
      wrapLines
      resizableColumns
      trackBy={trackBy}
      items={pageItems}
      columnDefinitions={columns}
      onRowClick={onRowClick ? ({ detail }) => onRowClick(detail.item) : undefined}
      header={
        header ? (
          <Header
            variant="h2"
            description={description}
            counter={`(${filteredItemsCount ?? items.length})`}
            actions={actions}
          >
            {header}
          </Header>
        ) : null
      }
      filter={
        <TextFilter
          {...filterProps}
          filteringPlaceholder={searchPlaceholder}
          filteringAriaLabel={searchPlaceholder}
          countText={`${filteredItemsCount ?? items.length}件`}
        />
      }
      pagination={
        <Pagination
          {...paginationProps}
          ariaLabels={{
            nextPageLabel: "次のページ",
            previousPageLabel: "前のページ",
            pageLabel: (page) => `${page}ページ`,
          }}
        />
      }
      ariaLabels={{
        tableLabel: header || "リソース一覧",
        sortAscending: "昇順に並べ替え",
        sortDescending: "降順に並べ替え",
      }}
    />
  );
}

export function Loading({ label = "読み込んでいます" }) {
  return (
    <Box padding="xxl" textAlign="center" color="text-body-secondary">
      <SpaceBetween direction="horizontal" size="xs" alignItems="center">
        <Spinner size="big" />
        <span role="status">{label}</span>
      </SpaceBetween>
    </Box>
  );
}

export function ErrorAlert({ error, onRetry }) {
  if (!error) return null;
  return (
    <Alert
      type="error"
      header="処理に失敗しました"
      action={
        onRetry ? (
          <Button iconName="refresh" onClick={onRetry}>
            再試行
          </Button>
        ) : undefined
      }
    >
      {error instanceof Error ? error.message : String(error)}
    </Alert>
  );
}

export function MermaidDiagram({ source }) {
  const reactId = useId();
  const renderId = useMemo(
    () => `hn-topology-${reactId.replaceAll(":", "")}`,
    [reactId],
  );
  const [svg, setSvg] = useState("");
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setSvg("");
    setError(null);
    if (!window.mermaid || !source) {
      setError(new Error("Mermaidを読み込めませんでした"));
      return () => {
        cancelled = true;
      };
    }
    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: document.documentElement.classList.contains("awsui-dark-mode")
        ? "dark"
        : "default",
      flowchart: { htmlLabels: true, curve: "basis" },
    });
    Promise.resolve(window.mermaid.render(renderId, source))
      .then((result) => {
        if (!cancelled) setSvg(result.svg);
      })
      .catch((renderError) => {
        if (!cancelled) setError(renderError);
      });
    return () => {
      cancelled = true;
    };
  }, [renderId, source]);

  if (error) return <ErrorAlert error={error} />;
  if (!svg) return <Loading label="トポロジー図を生成しています" />;
  return (
    <div
      className="topology-diagram"
      aria-label="オーバーレイトポロジー図"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
