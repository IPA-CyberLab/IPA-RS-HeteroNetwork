FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo gcc libc6-dev python3 curl ca-certificates libpam-modules \
    && rm -rf /var/lib/apt/lists/*
# Official v1.9.17p2 header, immutable revision and independently checked digest.
RUN curl -fsSL https://raw.githubusercontent.com/sudo-project/sudo/d1b48c651cec19fe37d1f0d3299d2283fb0f88e4/include/sudo_plugin.h -o /usr/local/include/sudo_plugin.h \
    && echo '11234d6e47e6da95adcb3ace71dc93f1d94b759aeca4cd938d829c076adfb35f  /usr/local/include/sudo_plugin.h' | sha256sum -c -
WORKDIR /opt/quorum-lifecycle
COPY deny_gate.c witness.c command.c gate_test.c test.py ./
RUN gcc -std=c11 -Wall -Wextra -Werror -fPIC -shared deny_gate.c -o deny_gate.so \
    && gcc -std=c11 -D_DEFAULT_SOURCE -DDISPOSABLE_LIFECYCLE_TEST -Wall -Wextra -Werror -fPIC -shared witness.c -o witness.so \
    && gcc -std=c11 -Wall -Wextra -Werror command.c -o command \
    && gcc -std=c11 -Wall -Wextra -Werror deny_gate.c gate_test.c -o gate_test \
    && ./gate_test \
    && useradd --uid 1000 --create-home fixture \
    && mkdir work
ENTRYPOINT ["python3", "/opt/quorum-lifecycle/test.py"]
