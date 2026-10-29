// Shared visual components; keep in sync with HeteroCloud apps/console/src/components/ui.
import {
  createContext,
  useContext,
  useEffect,
  useId,
  useRef,
  useState
} from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Circle,
  CircleAlert,
  CircleHelp,
  Copy,
  Download,
  ExternalLink,
  Folder,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  Sun,
  Terminal,
  TriangleAlert,
  Trash2,
  UserRound,
  X
} from "lucide-react";
function change(detail, event) {
  return { detail, preventDefault: () => event?.preventDefault() };
}
const iconMap = {
  "add-plus": Plus,
  add: Plus,
  refresh: RefreshCw,
  remove: Trash2,
  edit: Pencil,
  copy: Copy,
  close: X,
  check: Check,
  download: Download,
  external: ExternalLink,
  key: KeyRound,
  script: Terminal,
  terminal: Terminal,
  file: Folder,
  "file-open": Folder,
  "user-profile": UserRound,
  "user-profile-active": UserRound,
  folder: Folder,
  "sign-out": LogOut,
  "exit-full-screen": LogOut,
  settings: Settings,
  multiscreen: Server,
  "status-positive": CheckCircle2,
  "status-negative": CircleAlert,
  "status-pending": Circle,
  "light-dark": Moon,
  menu: Menu,
  search: Search
};
function Icon({ name, size = 16 }) {
  const Glyph = name ? iconMap[name] : void 0;
  return Glyph ? <Glyph size={size} aria-hidden="true" /> : null;
}
const sizes = {
  xxs: ".25rem",
  xs: ".5rem",
  s: ".75rem",
  m: "1rem",
  l: "1.5rem",
  xl: "2rem",
  xxl: "2.75rem"
};
const space = (value) => sizes[value ?? "m"] ?? "1rem";
export function SpaceBetween({
  children,
  size = "m",
  direction = "vertical",
  alignItems,
  ...props
}) {
  return <div
    className={`ui-stack ${direction === "horizontal" ? "ui-stack--row" : ""}`}
    style={{ gap: space(size), alignItems }}
    {...props.id ? { id: props.id } : {}}
  >
      {children}
    </div>;
}
export function Box({
  children,
  variant,
  color,
  fontWeight,
  fontSize,
  textAlign,
  padding,
  margin,
  float,
  className = ""
}) {
  const tag = ["h1", "h2", "h3", "h4", "p", "pre", "code", "small", "strong"].includes(
    variant
  ) ? variant : "div";
  const Tag = tag;
  return <Tag
    className={`ui-box ${variant ? `ui-box--${variant}` : ""} ${color ? `ui-text--${color}` : ""} ${className}`}
    style={{
      fontWeight: fontWeight === "bold" ? 700 : void 0,
      fontSize: fontSize ? space(fontSize) : void 0,
      textAlign,
      padding: typeof padding === "string" ? space(padding) : void 0,
      margin: typeof margin === "object" && margin?.vertical ? `${space(margin.vertical)} 0` : void 0,
      float
    }}
  >
      {children}
    </Tag>;
}
export function Header({
  children,
  variant = "h2",
  description,
  counter,
  actions
}) {
  const Tag = variant === "h1" ? "h1" : variant === "h3" ? "h3" : "h2";
  return <div className={`ui-section-header ui-section-header--${variant}`}>
      <div className="ui-section-header__copy">
        <Tag>
          {children}
          {counter && <span className="ui-counter">{counter}</span>}
        </Tag>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="ui-section-header__actions">{actions}</div>}
    </div>;
}
export function Container({ children, header }) {
  return <section className="card ui-card">
      <div className="ui-card__body">
        {header && <div className="ui-card__header">{header}</div>}
        {children}
      </div>
    </section>;
}
export function ContentLayout({ children, header }) {
  return <div className="ui-content-layout">
      {header && <div className="ui-content-layout__header">{header}</div>}
      {children}
    </div>;
}
export function ColumnLayout({ children, columns = 2 }) {
  return <div
    className="ui-columns"
    data-columns={Math.min(4, Math.max(1, Number(columns)))}
  >
      {children}
    </div>;
}
export function Link({
  children,
  href = "#",
  ariaLabel,
  external,
  externalIconAriaLabel,
  onFollow,
  ...props
}) {
  return <a
    className="ui-link"
    href={href}
    aria-label={ariaLabel}
    target={external ? "_blank" : props.target}
    rel={external ? "noopener noreferrer" : props.rel}
    onClick={(event) => {
      if (onFollow && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && event.button === 0)
        onFollow(change({ href, external }, event));
    }}
  >
      {children}
      {external && <ExternalLink size={13} aria-label={externalIconAriaLabel} />}
    </a>;
}
export function Button({
  children,
  variant,
  iconName,
  ariaLabel,
  href,
  external,
  target,
  disabled,
  loading,
  fullWidth,
  formAction,
  onClick,
  ...props
}) {
  const inline = variant === "inline-link" || variant === "link";
  const classes = inline ? "ui-inline-link" : `btn ui-btn ${variant === "primary" ? "btn-primary" : variant === "icon" ? "btn-ghost btn-square" : variant === "normal" || !variant ? "btn-outline" : "btn-ghost"} ${fullWidth ? "ui-btn--full" : ""}`;
  const inner = <>
      {loading ? <span
    className="loading loading-spinner loading-xs"
    aria-hidden="true"
  /> : <Icon name={iconName} />}
      {children}
    </>;
  if (href)
    return <a
      href={disabled || loading ? void 0 : href}
      className={classes}
      aria-label={ariaLabel}
      aria-disabled={disabled || loading || void 0}
      target={target || (external ? "_blank" : void 0)}
      rel={target === "_blank" || external ? "noopener noreferrer" : void 0}
      onClick={onClick}
    >
        {inner}
      </a>;
  return <button
    type={formAction === "submit" ? "submit" : "button"}
    className={classes}
    aria-label={ariaLabel}
    disabled={disabled || loading}
    onClick={onClick}
    title={props.title}
  >
      {inner}
    </button>;
}
export function Badge({ children, color = "blue" }) {
  const map = {
    green: "badge-success",
    red: "badge-error",
    blue: "badge-info",
    grey: "badge-neutral",
    grey2: "badge-neutral",
    yellow: "badge-warning",
    severityHigh: "badge-error",
    severityMedium: "badge-warning"
  };
  return <span className={`badge badge-soft ${map[color] ?? "badge-neutral"}`}>
      {children}
    </span>;
}
export function StatusIndicator({ children, type = "info" }) {
  const kind = type === "success" ? "success" : type === "error" ? "error" : type === "warning" ? "warning" : type === "loading" || type === "in-progress" || type === "pending" ? "loading" : "neutral";
  return <span className={`ui-status ui-status--${kind}`}>
      {kind === "loading" ? <span
    className="loading loading-spinner loading-xs"
    aria-hidden="true"
  /> : <span className="ui-status__dot" aria-hidden="true" />}
      {children}
    </span>;
}
export function Spinner({ size = "normal" }) {
  return <span
    className={`loading loading-spinner ${size === "big" ? "loading-md" : "loading-sm"}`}
    aria-hidden="true"
  />;
}
export function Alert({
  children,
  type = "info",
  header,
  action,
  dismissible,
  onDismiss
}) {
  const IconComponent = type === "error" ? CircleAlert : type === "warning" ? TriangleAlert : type === "success" ? CheckCircle2 : CircleHelp;
  return <div
    className={`alert ui-alert ui-alert--${type}`}
    role={type === "error" ? "alert" : "status"}
  >
      <IconComponent size={19} aria-hidden="true" />
      <div className="ui-alert__copy">
        {header && <strong>{header}</strong>}
        {children && <div>{children}</div>}
      </div>
      {action && <div>{action}</div>}
      {dismissible && <button
    type="button"
    className="btn btn-ghost btn-square btn-sm"
    aria-label="ダイアログを閉じる"
    onClick={onDismiss}
  >
          <X size={16} />
        </button>}
    </div>;
}
export function Flashbar({ items = [] }) {
  return <div className="ui-flashbar" aria-live="polite">
      {items.map((item, index) => <Alert
    key={item.id ?? index}
    type={item.type}
    dismissible={item.dismissible}
    onDismiss={item.onDismiss}
  >
          {item.content}
        </Alert>)}
    </div>;
}
const Field = createContext(null);
export function FormField({
  children,
  label,
  description,
  constraintText,
  errorText
}) {
  const id = useId(), descriptionId = description || constraintText ? `${id}-description` : void 0, errorId = errorText ? `${id}-error` : void 0;
  return <div className="fieldset ui-field">
      <div className="ui-field__label">
        {typeof label === "string" ? <label htmlFor={id}>{label}</label> : label}
      </div>
      {description && <p id={descriptionId} className="ui-field__description">
          {description}
        </p>}
      <Field.Provider value={{ id, descriptionId, errorId }}>
        {children}
      </Field.Provider>
      {constraintText && <p
    className="ui-field__hint"
    id={!description ? descriptionId : void 0}
  >
          {constraintText}
        </p>}
      {errorText && <p id={errorId} className="ui-field__error" role="alert">
          {errorText}
        </p>}
    </div>;
}
function fieldAttributes(field, ariaLabel) {
  return {
    id: field?.id,
    "aria-label": ariaLabel,
    "aria-describedby": [field?.descriptionId, field?.errorId].filter(Boolean).join(" ") || void 0,
    "aria-invalid": field?.errorId ? true : void 0
  };
}
export function Input({
  value = "",
  onChange,
  onKeyDown,
  ariaLabel,
  nativeInputAttributes,
  invalid,
  ...props
}) {
  const field = useContext(Field);
  return <input
    {...nativeInputAttributes}
    {...fieldAttributes(field, ariaLabel)}
    className={`input ui-input ${invalid || field?.errorId ? "input-error" : ""}`}
    value={value}
    type={props.type || "text"}
    inputMode={props.inputMode}
    step={props.step}
    autoComplete={props.autoComplete}
    disabled={props.disabled}
    readOnly={props.readOnly}
    placeholder={props.placeholder}
    onKeyDown={onKeyDown}
    onChange={(event) => onChange?.(change({ value: event.currentTarget.value }, event))}
  />;
}
export function Textarea({
  value = "",
  onChange,
  ariaLabel,
  ...props
}) {
  const field = useContext(Field);
  return <textarea
    {...fieldAttributes(field, ariaLabel)}
    className={`textarea ui-textarea ${field?.errorId ? "textarea-error" : ""}`}
    value={value}
    rows={props.rows ?? 3}
    disabled={props.disabled}
    placeholder={props.placeholder}
    onChange={(event) => onChange?.(change({ value: event.currentTarget.value }, event))}
  />;
}
export function Toggle({
  checked = false,
  onChange,
  children,
  disabled,
  ariaLabel
}) {
  const field = useContext(Field);
  return <label className="ui-toggle">
      <input
    type="checkbox"
    id={field?.id}
    className="toggle toggle-primary toggle-sm"
    checked={checked}
    disabled={disabled}
    aria-label={ariaLabel}
    aria-describedby={field?.descriptionId}
    onChange={(event) => onChange?.(change({ checked: event.currentTarget.checked }, event))}
  />
      <span>{children}</span>
    </label>;
}
export function Form({ children, header, actions, errorText }) {
  return <div className="ui-form">
      {header}
      {errorText && <div className="alert ui-alert ui-alert--error" role="alert">
          {errorText}
        </div>}
      {children}
      {actions && <div className="ui-form__actions">{actions}</div>}
    </div>;
}
function flattenOptions(options = []) {
  return options.flatMap(
    (option) => option.options ? flattenOptions(option.options) : [option]
  );
}
export function Select({
  options = [],
  selectedOption,
  onChange,
  ariaLabel,
  placeholder = "\u9078\u629E\u3057\u3066\u304F\u3060\u3055\u3044",
  disabled,
  statusType,
  recoveryText,
  onLoadItems
}) {
  const field = useContext(Field), all = flattenOptions(options), selected = selectedOption?.value ?? "";
  const known = all.some((option) => option.value === selected), hasEmpty = all.some((option) => option.value === "");
  return <div className="ui-select-wrap">
      <select
    {...fieldAttributes(field, ariaLabel)}
    className="select ui-select"
    value={selected}
    disabled={disabled}
    onChange={(event) => {
      const option = all.find(
        (item) => item.value === event.currentTarget.value
      );
      if (option) onChange?.(change({ selectedOption: option }, event));
    }}
  >
        {!hasEmpty && <option value="" disabled>
            {statusType === "loading" ? "\u8AAD\u307F\u8FBC\u307F\u4E2D" : placeholder}
          </option>}
        {selected && !known && <option value={selected}>{selectedOption?.label ?? selected}</option>}
        {all.map((option, index) => <option
    key={`${option.value}-${index}`}
    value={option.value ?? ""}
    disabled={option.disabled}
  >
            {option.label ?? option.value}
            {option.labelTag ? ` \xB7 ${option.labelTag}${typeof option.description === "string" ? ` \xB7 ${option.description}` : ""}` : ""}
          </option>)}
      </select>
      {statusType === "error" && onLoadItems && <button
    type="button"
    className="ui-inline-link"
    onClick={() => onLoadItems(change({ filteringText: "", firstPage: true }))}
  >
          {recoveryText ?? "\u518D\u8A66\u884C"}
        </button>}
    </div>;
}
export function Multiselect({
  options = [],
  selectedOptions = [],
  onChange,
  ariaLabel,
  placeholder = "\u9078\u629E\u3057\u3066\u304F\u3060\u3055\u3044",
  disabled,
  filteringPlaceholder = "\u691C\u7D22"
}) {
  const field = useContext(Field), [open, setOpen] = useState(false), [filter, setFilter] = useState("");
  const root = useRef(null), all = flattenOptions(options);
  useEffect(() => {
    if (!open) return;
    const handler = (event) => {
      if (!root.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", handler);
    return () => document.removeEventListener("pointerdown", handler);
  }, [open]);
  const toggle = (option) => {
    if (disabled || option.disabled) return;
    const exists = selectedOptions.some((item) => item.value === option.value);
    onChange?.(
      change({
        selectedOptions: exists ? selectedOptions.filter((item) => item.value !== option.value) : [...selectedOptions, option]
      })
    );
  };
  const shown = all.filter(
    (option) => `${option.label ?? ""} ${option.value ?? ""}`.toLowerCase().includes(filter.toLowerCase())
  );
  return <div className="ui-multiselect" ref={root}>
      <button
    type="button"
    {...fieldAttributes(field, ariaLabel)}
    className="select ui-multiselect__trigger"
    disabled={disabled}
    aria-haspopup="listbox"
    aria-expanded={open}
    onClick={() => setOpen(!open)}
  >
        {selectedOptions.length ? `${selectedOptions.length}\u4EF6\u3092\u9078\u629E` : placeholder}
      </button>
      {selectedOptions.length > 0 && <div className="ui-selected-options">
          {selectedOptions.map((option, index) => <span
    className="badge badge-soft badge-primary"
    key={`${option.value}-${index}`}
  >
              {option.label ?? option.value}
              <button
    type="button"
    disabled={disabled}
    aria-label={`${option.label ?? option.value} \u3092\u524A\u9664`}
    onClick={() => toggle(option)}
  >
                <X size={13} />
              </button>
            </span>)}
        </div>}
      {open && <div className="ui-option-menu">
          <input
    className="input ui-input input-sm"
    aria-label={filteringPlaceholder}
    placeholder={filteringPlaceholder}
    value={filter}
    onChange={(e) => setFilter(e.currentTarget.value)}
  />
          <div role="listbox" aria-multiselectable="true">
            {shown.map((option, index) => {
    const selected = selectedOptions.some(
      (item) => item.value === option.value
    );
    return <button
      type="button"
      role="option"
      aria-selected={selected}
      disabled={option.disabled}
      key={`${option.value}-${index}`}
      onClick={() => toggle(option)}
    >
                  <span
      className={`ui-option-check ${selected ? "is-selected" : ""}`}
    >
                    {selected && <Check size={13} />}
                  </span>
                  <span>
                    {option.label ?? option.value}
                    {option.description && <small>{option.description}</small>}
                  </span>
                </button>;
  })}
            {!shown.length && <p className="ui-empty-inline">該当する項目がありません。</p>}
          </div>
        </div>}
    </div>;
}
export function SegmentedControl({
  options = [],
  selectedId,
  onChange,
  label
}) {
  return <div className="join ui-segmented" role="group" aria-label={label}>
      {options.map((option) => <button
    type="button"
    key={option.id}
    className={`btn btn-sm join-item ${selectedId === option.id ? "btn-primary" : "btn-ghost"}`}
    aria-pressed={selectedId === option.id}
    disabled={option.disabled}
    onClick={() => onChange?.(change({ selectedId: option.id }))}
  >
          {option.text}
        </button>)}
    </div>;
}
export function Autosuggest({
  options = [],
  value = "",
  onChange,
  onSelect,
  ariaLabel,
  placeholder,
  empty
}) {
  const [open, setOpen] = useState(false), [active, setActive] = useState(-1), id = useId();
  const root = useRef(null);
  const shown = options.filter(
    (option) => [
      option.label,
      option.value,
      option.description,
      ...option.filteringTags ?? []
    ].filter((v) => typeof v === "string").join(" ").toLowerCase().includes(value.toLowerCase())
  );
  useEffect(() => {
    if (!open) return;
    const handler = (event) => {
      if (!root.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", handler);
    return () => document.removeEventListener("pointerdown", handler);
  }, [open]);
  const choose = (option) => {
    setOpen(false);
    onSelect?.(change({ value: option.value ?? "" }));
  };
  return <div className="ui-autosuggest" ref={root}>
      <Search size={17} className="ui-autosuggest__icon" aria-hidden="true" />
      <input
    className="input ui-input ui-autosuggest__input"
    value={value}
    placeholder={placeholder}
    aria-label={ariaLabel}
    role="combobox"
    aria-expanded={open}
    aria-controls={`${id}-list`}
    aria-autocomplete="list"
    aria-activedescendant={open && shown[active] ? `${id}-${active}` : void 0}
    onFocus={() => setOpen(true)}
    onChange={(event) => {
      setActive(-1);
      setOpen(true);
      onChange?.(change({ value: event.currentTarget.value }, event));
    }}
    onKeyDown={(event) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setOpen(true);
        setActive(Math.min(active + 1, shown.length - 1));
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setActive(Math.max(0, active - 1));
      } else if (event.key === "Enter" && open && shown[active]) {
        event.preventDefault();
        choose(shown[active]);
      } else if (event.key === "Escape") setOpen(false);
    }}
  />
      {open && <div className="ui-option-menu" id={`${id}-list`} role="listbox">
          {shown.map((option, index) => <button
    type="button"
    role="option"
    id={`${id}-${index}`}
    aria-selected={active === index}
    key={option.value ?? index}
    onMouseDown={(e) => e.preventDefault()}
    onClick={() => choose(option)}
  >
              <span>
                {option.label ?? option.value}
                {option.description && <small>{option.description}</small>}
              </span>
            </button>)}
          {!shown.length && <p className="ui-empty-inline">
              {empty ?? "\u8A72\u5F53\u3059\u308B\u9805\u76EE\u304C\u3042\u308A\u307E\u305B\u3093\u3002"}
            </p>}
        </div>}
    </div>;
}
let modalDepth = 0;
let previousOverflow = "";
const modalStack = [];
export function Modal({
  children,
  visible,
  header,
  footer,
  onDismiss,
  size = "medium"
}) {
  const id = useId(), dialog = useRef(null), titleId = `${id}-title`;
  const dismissRef = useRef(onDismiss);
  dismissRef.current = onDismiss;
  useEffect(() => {
    if (!visible) return;
    const previousFocus = document.activeElement;
    if (modalDepth++ === 0) {
      previousOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    }
    modalStack.push(id);
    const timer = window.setTimeout(
      () => (dialog.current?.querySelector(
        ".ui-modal__body input:not([disabled]),.ui-modal__body select:not([disabled]),.ui-modal__body textarea:not([disabled])"
      ) ?? dialog.current?.querySelector("button:not([disabled])"))?.focus(),
      0
    );
    const keydown = (event) => {
      if (modalStack.at(-1) !== id) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        dismissRef.current?.();
        return;
      }
      if (event.key !== "Tab" || !dialog.current) return;
      const items = [
        ...dialog.current.querySelectorAll(
          'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'
        )
      ].filter((el) => !el.closest("[hidden]"));
      if (!items.length) {
        event.preventDefault();
        dialog.current.focus();
        return;
      }
      const first = items[0], last = items[items.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialog.current.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", keydown, true);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("keydown", keydown, true);
      const index = modalStack.indexOf(id);
      if (index >= 0) modalStack.splice(index, 1);
      if (--modalDepth === 0) document.body.style.overflow = previousOverflow;
      previousFocus?.isConnected && previousFocus.focus();
    };
  }, [visible, id]);
  if (!visible) return null;
  return createPortal(
    <div
      className="modal modal-open ui-modal"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onDismiss?.();
      }}
    >
      <div
      className={`modal-box ui-modal__box ui-modal__box--${size}`}
      ref={dialog}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      tabIndex={-1}
    >
        <div className="ui-modal__header">
          <h2 id={titleId}>{header}</h2>
          <button
      type="button"
      className="btn btn-ghost btn-square btn-sm"
      aria-label="ダイアログを閉じる"
      onClick={onDismiss}
    >
            <X size={18} />
          </button>
        </div>
        <div className="ui-modal__body">{children}</div>
        {footer && <div className="ui-modal__footer">{footer}</div>}
      </div>
    </div>,
    document.body
  );
}
function navigationIcon(href = "") {
  if (href.includes("overview")) return LayoutDashboard;
  if (href.includes("node") || href.includes("gpu")) return Server;
  if (href.includes("vpc") || href.includes("topology") || href.includes("path") || href.includes("route"))
    return Network;
  if (href.includes("acl") || href.includes("iam") || href.includes("audit"))
    return Shield;
  if (href.includes("settings")) return Settings;
  if (href.includes("cli")) return Terminal;
  if (href.includes("flow") || href.includes("transport")) return Activity;
  if (href.includes("registry") || href.includes("bucket") || href.includes("backup"))
    return Folder;
  return Circle;
}
export function SideNavigation({
  header,
  items = [],
  activeHref,
  onFollow
}) {
  const follow = (href, external, event) => {
    if (onFollow && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && event.button === 0)
      onFollow(change({ href, external }, event));
  };
  const render = (item, index) => {
    if (item.type === "divider")
      return <li className="ui-nav-divider" key={`divider-${index}`} />;
    if (item.type === "section")
      return <li className="ui-nav-section" key={item.text ?? index}>
          <details open>
            <summary>
              {item.text}
              <ChevronDown size={15} aria-hidden="true" />
            </summary>
            <ul>{(item.items ?? []).map(render)}</ul>
          </details>
        </li>;
    const href = item.href ?? "#", active = activeHref === href || href !== "/overview" && href !== "#/overview" && activeHref?.startsWith(href + "/");
    const Glyph = navigationIcon(href);
    return <li key={href}>
        <a
      href={href}
      className={active ? "is-active" : ""}
      aria-current={active ? "page" : void 0}
      onClick={(event) => follow(href, item.external, event)}
    >
          <Glyph size={17} aria-hidden="true" />
          <span>{item.text}</span>
          {item.info != null && <span className="ui-nav-info">{item.info}</span>}
        </a>
      </li>;
  };
  return <nav className="ui-side-nav" aria-label="メインナビゲーション">
      {header?.text && <div className="ui-side-nav__title">{header.text}</div>}
      <ul className="menu ui-menu">{items.map(render)}</ul>
    </nav>;
}
export function BreadcrumbGroup({
  items = [],
  onFollow
}) {
  const normalized = items.filter(
    (item, index) => index === items.length - 1 || item.href !== items[index + 1]?.href
  );
  return <nav aria-label="パンくずリスト" className="ui-breadcrumbs">
      <ol>
        {normalized.map((item, index) => <li key={`${item.href}-${index}`}>
            {index === normalized.length - 1 ? <span aria-current="page">{item.text}</span> : <a
    href={item.href}
    onClick={(event) => {
      if (onFollow && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && event.button === 0)
        onFollow(change({ href: item.href }, event));
    }}
  >
                {item.text}
              </a>}
          </li>)}
      </ol>
    </nav>;
}
export function TopNavigation({
  identity,
  search,
  utilities = []
}) {
  const [mobileSearch, setMobileSearch] = useState(false);
  const cloud = String(identity?.title ?? "").startsWith("HeteroCloud");
  const [theme, setTheme] = useState(
    () => typeof document !== "undefined" && (localStorage.getItem("heterocloud_theme") || document.documentElement.dataset.theme) === "dark" ? "dark" : "light"
  );
  useEffect(() => {
    if (!cloud) return;
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("heterocloud_theme", theme);
  }, [theme, cloud]);
  useEffect(() => {
    const close = (event) => {
      if (event.target?.closest?.(".ui-top-menu")) return;
      document.querySelectorAll(".ui-top-menu[open]").forEach((menu) => menu.open = false);
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, []);
  return <div className="navbar ui-topnav">
      <a
    className="ui-brand"
    href={identity?.href ?? "/"}
    onClick={(event) => {
      if (identity?.onFollow && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && event.button === 0)
        identity.onFollow(change({ href: identity.href ?? "/" }, event));
    }}
  >
        <span className="ui-brand__mark" aria-hidden="true">
          <span />
          <span />
          <span />
          <span />
        </span>
        <strong>{identity?.title}</strong>
      </a>
      <div className={`ui-topnav__search ${mobileSearch ? "is-open" : ""}`}>
        {search}
      </div>
      <div className="ui-topnav__utilities">
        {search && <button
    type="button"
    className="btn btn-ghost btn-square ui-topnav__mobile-search"
    aria-label={mobileSearch ? "\u691C\u7D22\u3092\u9589\u3058\u308B" : "\u691C\u7D22\u3092\u958B\u304F"}
    onClick={() => setMobileSearch(!mobileSearch)}
  >
            {mobileSearch ? <X size={18} /> : <Search size={18} />}
          </button>}
        {cloud && <button
    type="button"
    className="btn btn-ghost btn-square ui-topnav__theme"
    aria-label={theme === "dark" ? "\u30E9\u30A4\u30C8\u30E2\u30FC\u30C9\u306B\u5207\u308A\u66FF\u3048" : "\u30C0\u30FC\u30AF\u30E2\u30FC\u30C9\u306B\u5207\u308A\u66FF\u3048"}
    onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
  >
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>}
        {utilities.map(
    (utility, index) => utility.type === "button" ? <button
      type="button"
      key={index}
      className="btn btn-ghost ui-topnav__utility"
      aria-label={utility.ariaLabel || utility.text}
      onClick={utility.onClick}
    >
              {utility.iconName === "light-dark" && String(utility.ariaLabel).includes("\u30E9\u30A4\u30C8") ? <Sun size={17} /> : <Icon name={utility.iconName} />}
              <span>{utility.text}</span>
            </button> : <details className="dropdown dropdown-end ui-top-menu" key={index}>
              <summary
      className="btn btn-ghost ui-topnav__utility"
      aria-label={utility.ariaLabel || utility.text}
    >
                <Icon name={utility.iconName} />
                {utility.ariaLabel === "\u64CD\u4F5C\u5BFE\u8C61\u306E\u7D44\u7E54" && <span className="ui-topnav__utility-label">組織</span>}
                <span className="ui-topnav__utility-text">{utility.text}</span>
                <ChevronDown size={14} aria-hidden="true" />
              </summary>
              <ul className="dropdown-content menu ui-dropdown" role="menu">
                {utility.description && <li className="ui-dropdown__description">
                    {utility.description}
                  </li>}
                {(utility.items ?? []).map((item) => <li key={item.id}>
                    <button
      role="menuitem"
      type="button"
      onClick={(event) => {
        event.currentTarget.closest("details")?.removeAttribute("open");
        utility.onItemClick?.(change({ id: item.id }, event));
      }}
    >
                      <Icon name={item.iconName} />
                      {item.text}
                    </button>
                  </li>)}
              </ul>
            </details>
  )}
      </div>
    </div>;
}
export function AppLayout({
  navigationOpen = true,
  onNavigationChange,
  navigation,
  breadcrumbs,
  notifications,
  content,
  ariaLabels = {}
}) {
  return <div className={`ui-layout ${navigationOpen ? "is-nav-open" : ""}`}>
      <aside
    className="ui-layout__sidebar"
    aria-label={ariaLabels.navigation}
    onClickCapture={(event) => {
      if (window.innerWidth < 1024 && event.target.closest("a"))
        onNavigationChange?.(change({ open: false }));
    }}
  >
        {navigation}
      </aside>
      {navigationOpen && <button
    className="ui-layout__backdrop"
    type="button"
    aria-label={ariaLabels.navigationClose ?? "\u30CA\u30D3\u30B2\u30FC\u30B7\u30E7\u30F3\u3092\u9589\u3058\u308B"}
    onClick={() => onNavigationChange?.(change({ open: false }))}
  />}
      <main className="ui-layout__main">
        <div className="ui-layout__content">
          <div className="ui-layout__crumbrow">
            <button
    type="button"
    className="btn btn-ghost btn-square btn-sm ui-layout__menu-toggle"
    aria-label={navigationOpen ? ariaLabels.navigationClose ?? "\u30CA\u30D3\u30B2\u30FC\u30B7\u30E7\u30F3\u3092\u9589\u3058\u308B" : ariaLabels.navigationToggle ?? "\u30CA\u30D3\u30B2\u30FC\u30B7\u30E7\u30F3\u3092\u958B\u304F"}
    onClick={() => onNavigationChange?.(change({ open: !navigationOpen }))}
  >
              <Menu size={18} />
            </button>
            {breadcrumbs}
          </div>
          {notifications}
          {content}
        </div>
      </main>
    </div>;
}
export function ExpandableSection({ headerText, children }) {
  return <details className="collapse ui-expandable">
      <summary className="collapse-title">
        {headerText}
        <ChevronDown size={16} />
      </summary>
      <div className="collapse-content">{children}</div>
    </details>;
}
export function Table({
  items = [],
  columnDefinitions = [],
  header,
  filter,
  pagination,
  empty,
  loading,
  loadingText,
  onRowClick,
  onSortingChange,
  sortingColumn,
  sortingDescending,
  columnDisplay,
  ariaLabels,
  trackBy
}) {
  const [ownSort, setOwnSort] = useState(null);
  const visible = columnDefinitions.filter(
    (col) => !columnDisplay || columnDisplay.find((d) => String(d.id) === String(col.id))?.visible !== false
  );
  const sorted = !onSortingChange && ownSort ? [...items].sort((a, b) => {
    const c = ownSort.column;
    const value = c.sortingComparator ? c.sortingComparator(a, b) : String(
      a[c.sortingField ?? c.id ?? ""] ?? ""
    ).localeCompare(
      String(b[c.sortingField ?? c.id ?? ""] ?? ""),
      "ja",
      { numeric: true }
    );
    return ownSort.desc ? -value : value;
  }) : items;
  return <div className="ui-table-card card">
      <div className="ui-table-card__header">
        {header}
        {filter}
      </div>
      <div className="ui-table-scroll" tabIndex={0}>
        <table
    className="table ui-table"
    aria-label={ariaLabels?.tableLabel ?? "\u30EA\u30BD\u30FC\u30B9\u4E00\u89A7"}
  >
          <thead>
            <tr>
              {visible.map((column, index) => {
    const sortable = Boolean(
      column.sortingField || column.sortingComparator
    );
    const active = (sortingColumn?.id ?? ownSort?.column.id) === column.id;
    const descending = onSortingChange ? sortingDescending : ownSort?.desc;
    return <th
      key={column.id ?? index}
      scope="col"
      aria-sort={active ? descending ? "descending" : "ascending" : void 0}
    >
                    {sortable ? <button
      type="button"
      className="ui-sort"
      onClick={() => {
        const next = active ? !descending : false;
        if (onSortingChange)
          onSortingChange(
            change({
              sortingColumn: column,
              isDescending: next
            })
          );
        else setOwnSort({ column, desc: next });
      }}
    >
                        {column.header}
                        {active ? descending ? <ArrowDown size={14} /> : <ArrowUp size={14} /> : <span className="ui-sort__hint">↕</span>}
                      </button> : column.header}
                  </th>;
  })}
            </tr>
          </thead>
          <tbody>
            {!loading && sorted.map((item, index) => <tr
    key={typeof trackBy === "function" ? trackBy(item) : typeof trackBy === "string" ? String(item[trackBy] ?? index) : index}
    className={onRowClick ? "ui-table__row--clickable" : ""}
    onClick={(event) => {
      if (!event.target.closest(
        "a,button,input,select,textarea,[role=button]"
      ))
        onRowClick?.(change({ item }, event));
    }}
  >
                  {visible.map((column, i) => <td key={column.id ?? i}>
                      {column.cell ? column.cell(item) : null}
                    </td>)}
                </tr>)}
          </tbody>
        </table>
      </div>
      {loading ? <div className="ui-table__empty">
          <Spinner /> {loadingText ?? "\u8AAD\u307F\u8FBC\u3093\u3067\u3044\u307E\u3059"}
        </div> : !sorted.length ? <div className="ui-table__empty">{empty ?? "\u30C7\u30FC\u30BF\u304C\u3042\u308A\u307E\u305B\u3093"}</div> : null}
      {pagination && <div className="ui-table__footer">{pagination}</div>}
    </div>;
}
export function TextFilter({
  filteringText = "",
  filteringPlaceholder,
  filteringAriaLabel,
  onChange,
  countText
}) {
  return <div className="ui-table-filter">
      <div className="ui-search-input">
        <Search size={16} aria-hidden="true" />
        <input
    className="input ui-input"
    value={filteringText}
    aria-label={filteringAriaLabel ?? filteringPlaceholder ?? "\u691C\u7D22"}
    placeholder={filteringPlaceholder}
    onChange={(event) => onChange?.(
      change({ filteringText: event.currentTarget.value }, event)
    )}
  />
      </div>
      {countText && <span className="ui-muted">{countText}</span>}
    </div>;
}
export function Pagination({
  currentPageIndex = 1,
  pagesCount = 1,
  onChange,
  ariaLabels = {}
}) {
  return <nav className="join ui-pagination" aria-label="ページ移動">
      <button
    type="button"
    className="btn btn-ghost btn-sm join-item"
    disabled={currentPageIndex <= 1}
    aria-disabled={currentPageIndex <= 1}
    aria-label={ariaLabels.previousPageLabel ?? "\u524D\u306E\u30DA\u30FC\u30B8"}
    onClick={() => onChange?.(change({ currentPageIndex: currentPageIndex - 1 }))}
  >
        <ChevronLeft size={16} />
      </button>
      <span className="ui-pagination__count">
        {currentPageIndex} / {pagesCount}
      </span>
      <button
    type="button"
    className="btn btn-ghost btn-sm join-item"
    disabled={currentPageIndex >= pagesCount}
    aria-disabled={currentPageIndex >= pagesCount}
    aria-label={ariaLabels.nextPageLabel ?? "\u6B21\u306E\u30DA\u30FC\u30B8"}
    onClick={() => onChange?.(change({ currentPageIndex: currentPageIndex + 1 }))}
  >
        <ChevronRight size={16} />
      </button>
    </nav>;
}
export function Cards({
  items = [],
  header,
  empty,
  cardDefinition,
  trackBy
}) {
  return <section className="ui-card-collection">
      {header}
      {items.length ? <div className="ui-cards-grid">
          {items.map((item, index) => <article
    className="card ui-service-card"
    key={typeof trackBy === "string" ? String(item[trackBy] ?? index) : index}
  >
              <div className="ui-service-card__title">
                {cardDefinition.header(item)}
                <ChevronRight size={16} aria-hidden="true" />
              </div>
              {cardDefinition.sections?.map((section) => <div className="ui-service-card__section" key={section.id}>
                  {section.header && <span>{section.header}</span>}
                  <div>{section.content(item)}</div>
                </div>)}
            </article>)}
        </div> : <div className="ui-card-collection__empty">{empty}</div>}
    </section>;
}
export function KeyValuePairs({ items = [], columns = 2 }) {
  return <dl className="ui-key-values" data-columns={columns}>
      {items.filter(Boolean).map((item, index) => <div key={index}>
          <dt>{item.label}</dt>
          <dd>{item.value ?? "\u2014"}</dd>
        </div>)}
    </dl>;
}
export function ProgressBar({
  value = 0,
  label,
  description,
  additionalInfo,
  status
}) {
  return <div className="ui-progress">
      <div className="ui-progress__label">
        <strong>{label}</strong>
        <span>{additionalInfo ?? `${Math.round(value)}%`}</span>
      </div>
      <progress
    className={`progress ${status === "error" ? "progress-error" : "progress-primary"}`}
    value={Math.max(0, Math.min(100, value))}
    max="100"
    aria-label={typeof label === "string" ? label : void 0}
  />
      {description && <p className="ui-muted">{description}</p>}
    </div>;
}
export function CopyToClipboard({
  textToCopy,
  copyButtonAriaLabel = "\u30B3\u30D4\u30FC",
  copySuccessText = "\u30B3\u30D4\u30FC\u3057\u307E\u3057\u305F",
  copyErrorText = "\u30B3\u30D4\u30FC\u3067\u304D\u307E\u305B\u3093\u3067\u3057\u305F"
}) {
  const [status, setStatus] = useState("");
  return <span className="ui-copy">
      <button
    type="button"
    className="btn btn-ghost btn-square btn-sm"
    aria-label={copyButtonAriaLabel}
    onClick={async () => {
      try {
        await navigator.clipboard.writeText(textToCopy);
        setStatus(copySuccessText);
      } catch {
        setStatus(copyErrorText);
      }
    }}
  >
        <Copy size={16} />
      </button>
      <span className="sr-only" role="status">
        {status}
      </span>
    </span>;
}
export function Tabs({
  tabs = [],
  activeTabId,
  onChange
}) {
  const [own, setOwn] = useState(tabs[0]?.id), active = activeTabId ?? own, id = useId();
  const select = (next) => {
    setOwn(next);
    onChange?.(change({ activeTabId: next }));
  };
  return <div>
      <div className="tabs tabs-border ui-tabs" role="tablist">
        {tabs.map((tab, index) => <button
    type="button"
    role="tab"
    key={tab.id}
    id={`${id}-${tab.id}`}
    aria-selected={active === tab.id}
    aria-controls={`${id}-${tab.id}-panel`}
    tabIndex={active === tab.id ? 0 : -1}
    className={`tab ${active === tab.id ? "tab-active" : ""}`}
    onClick={() => select(tab.id)}
    onKeyDown={(event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft")
        return;
      event.preventDefault();
      const next = tabs[(index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
      select(next.id);
      document.getElementById(`${id}-${next.id}`)?.focus();
    }}
  >
            {tab.label}
          </button>)}
      </div>
      {tabs.map(
    (tab) => active === tab.id ? <div
      key={tab.id}
      role="tabpanel"
      id={`${id}-${tab.id}-panel`}
      aria-labelledby={`${id}-${tab.id}`}
      className="ui-tab-panel"
    >
            {tab.content}
          </div> : null
  )}
    </div>;
}
export function AttributeEditor({
  items = [],
  definition = [],
  onAddButtonClick,
  onRemoveButtonClick,
  addButtonText,
  removeButtonText,
  removeButtonAriaLabel,
  empty
}) {
  return <div className="ui-attribute-editor">
      {!items.length && empty}
      {items.map((item, index) => <section className="ui-attribute-row" key={index}>
          <div className="ui-attribute-row__header">
            <strong>ルール {index + 1}</strong>
            <button
    type="button"
    className="btn btn-ghost btn-sm"
    aria-label={removeButtonAriaLabel?.(item) ?? removeButtonText}
    onClick={() => onRemoveButtonClick?.(change({ itemIndex: index, item }))}
  >
              <Trash2 size={15} />
              {removeButtonText}
            </button>
          </div>
          <div className="ui-attribute-grid">
            {definition.map((field, i) => <FormField key={i} label={field.label} description={field.info}>
                {field.control(item, index)}
              </FormField>)}
          </div>
        </section>)}
      <Button iconName="add-plus" onClick={onAddButtonClick}>
        {addButtonText ?? "\u8FFD\u52A0"}
      </Button>
    </div>;
}
export function useCollection(source, settings) {
  const [filteringText, setFilteringText] = useState("");
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState(null);
  const filtered = filteringText && settings.filtering?.filteringFunction ? source.filter(
    (item) => settings.filtering.filteringFunction(item, filteringText)
  ) : source;
  const ordered = sort ? [...filtered].sort((a, b) => {
    const column = sort.column;
    const n = column.sortingComparator ? column.sortingComparator(a, b) : String(
      a[column.sortingField ?? column.id ?? ""] ?? ""
    ).localeCompare(
      String(b[column.sortingField ?? column.id ?? ""] ?? ""),
      "ja",
      { numeric: true }
    );
    return sort.desc ? -n : n;
  }) : filtered;
  const size = settings.pagination?.pageSize ?? Math.max(source.length, 1), pagesCount = Math.max(1, Math.ceil(ordered.length / size)), currentPageIndex = Math.min(page, pagesCount);
  return {
    items: ordered.slice(
      (currentPageIndex - 1) * size,
      currentPageIndex * size
    ),
    filteredItemsCount: filtered.length,
    collectionProps: {
      empty: filteringText ? settings.filtering?.noMatch : settings.filtering?.empty,
      sortingColumn: sort?.column,
      sortingDescending: sort?.desc,
      onSortingChange: ({
        detail
      }) => setSort({ column: detail.sortingColumn, desc: detail.isDescending })
    },
    filterProps: {
      filteringText,
      onChange: ({ detail }) => {
        setFilteringText(detail.filteringText);
        setPage(1);
      }
    },
    paginationProps: {
      currentPageIndex,
      pagesCount,
      onChange: ({ detail }) => setPage(detail.currentPageIndex)
    }
  };
}
export function BarChart({
  series = [],
  height = 240,
  ariaLabel,
  yTitle,
  empty
}) {
  const points = series.flatMap((s) => s.data ?? []), max = Math.max(1, ...points.map((p) => Number(p.y) || 0));
  if (!points.length)
    return <div className="ui-chart-empty">{empty ?? "\u30C7\u30FC\u30BF\u304C\u3042\u308A\u307E\u305B\u3093"}</div>;
  return <div
    className="ui-bar-chart"
    role="img"
    aria-label={ariaLabel ?? yTitle ?? "\u68D2\u30B0\u30E9\u30D5"}
    style={{ minHeight: height }}
  >
      {points.map((p, index) => <div className="ui-bar-chart__item" key={index}>
          <span className="ui-bar-chart__value">{p.y}</span>
          <div className="ui-bar-chart__track">
            <div
    className="ui-bar-chart__bar"
    style={{
      height: `${Math.max(0, (Number(p.y) || 0) / max) * 100}%`
    }}
  />
          </div>
          <span className="ui-bar-chart__label">{String(p.x)}</span>
        </div>)}
    </div>;
}
export function LineChart({
  series = [],
  height = 220,
  ariaLabel,
  loadingText,
  statusType,
  empty,
  i18nStrings
}) {
  const points = series.flatMap((s) => s.data ?? []).filter(
    (p) => Number.isFinite(Number(p.y)) && Number.isFinite(new Date(p.x).getTime())
  );
  if (!points.length)
    return <div className="ui-chart-empty" style={{ minHeight: height }}>
        {statusType === "loading" ? loadingText ?? "\u8AAD\u307F\u8FBC\u3093\u3067\u3044\u307E\u3059" : empty ?? "\u30C7\u30FC\u30BF\u304C\u3042\u308A\u307E\u305B\u3093"}
      </div>;
  const xs = points.map((p) => new Date(p.x).getTime()), ys = points.map((p) => Number(p.y)), xmin = Math.min(...xs), xmax = Math.max(...xs), ymin = Math.min(0, ...ys), ymax = Math.max(...ys, ymin + 1);
  const x = (p) => 24 + (new Date(p.x).getTime() - xmin) / (xmax - xmin || 1) * 752, y = (p) => 180 - (Number(p.y) - ymin) / (ymax - ymin) * 155;
  const formatY = (value) => i18nStrings?.yTickFormatter ? i18nStrings.yTickFormatter(value) : String(Math.round(value * 100) / 100);
  return <div className="ui-line-chart">
      <div className="ui-line-chart__plot">
        <div className="ui-line-chart__axis" aria-hidden="true">
          <span>{formatY(ymax)}</span>
          <span>{formatY((ymin + ymax) / 2)}</span>
          <span>{formatY(ymin)}</span>
        </div>
        <svg
    viewBox="0 0 800 200"
    width="100%"
    height={height}
    preserveAspectRatio="none"
    role="img"
    aria-label={ariaLabel ?? "\u63A8\u79FB"}
  >
          <line x1="24" y1="180" x2="776" y2="180" className="ui-chart-axis" />
          {series.map((s, index) => <g key={s.title ?? index}>
              <polyline
    fill="none"
    className="ui-chart-line"
    points={(s.data ?? []).filter(
      (p) => Number.isFinite(Number(p.y)) && Number.isFinite(new Date(p.x).getTime())
    ).map((p) => `${x(p)},${y(p)}`).join(" ")}
  />
              {(s.data ?? []).filter(
    (p) => Number.isFinite(Number(p.y)) && Number.isFinite(new Date(p.x).getTime())
  ).map((p, i) => <circle
    key={i}
    cx={x(p)}
    cy={y(p)}
    r="3"
    tabIndex={0}
    className="ui-chart-point"
  >
                    <title>{`${s.title ?? ""} ${new Date(p.x).toLocaleString()}: ${p.y}`}</title>
                  </circle>)}
            </g>)}
        </svg>
      </div>
      <div className="ui-chart-range">
        <span>{new Date(xmin).toLocaleString()}</span>
        <span>{new Date(xmax).toLocaleString()}</span>
      </div>
    </div>;
}
export function TagInput({
  values = [],
  onChange,
  placeholder = "\u8FFD\u52A0\u3059\u308B\u5024",
  ariaLabel = "\u5024\u3092\u8FFD\u52A0",
  disabled = false
}) {
  const [draft, setDraft] = useState("");
  const field = useContext(Field);
  const add = () => {
    const entries = draft.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean);
    if (!entries.length) return;
    onChange([.../* @__PURE__ */ new Set([...values, ...entries])]);
    setDraft("");
  };
  return <div
    className="ui-tag-input"
    onBlur={(event) => {
      if (!disabled && !event.currentTarget.contains(event.relatedTarget))
        add();
    }}
  >
      <div className="ui-tag-input__entry">
        <input
    {...fieldAttributes(field, ariaLabel)}
    className="input ui-input"
    value={draft}
    placeholder={placeholder}
    disabled={disabled}
    onChange={(e) => setDraft(e.currentTarget.value)}
    onKeyDown={(e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        add();
      }
    }}
  />
        <Button
    disabled={disabled || !draft.trim()}
    iconName="add-plus"
    onClick={add}
  >
          追加
        </Button>
      </div>
      {values.length > 0 && <ul className="ui-tags">
          {values.map((value) => <li className="badge badge-soft badge-primary" key={value}>
              {value}
              <button
    type="button"
    disabled={disabled}
    aria-label={`${value} \u3092\u524A\u9664`}
    onClick={() => onChange(values.filter((v) => v !== value))}
  >
                <X size={13} />
              </button>
            </li>)}
        </ul>}
    </div>;
}
