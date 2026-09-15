"""Machine-readable Ansible results for Terraform's drift-aware entry point."""
import json
from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "hnn_json"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = []

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if not ignore_errors:
            self.errors.append({"host": result._host.get_name(), "task": result._task.get_name(),
                                "message": "redacted" if result._result.get("_ansible_no_log") else result._result.get("msg", "failed")})

    def v2_runner_on_unreachable(self, result):
        self.errors.append({"host": result._host.get_name(), "task": "SSH", "message": result._result.get("msg", "unreachable")})

    def v2_playbook_on_stats(self, stats):
        self._display.display(json.dumps({"hosts": {h: stats.summarize(h) for h in sorted(stats.processed)}, "errors": self.errors}))
