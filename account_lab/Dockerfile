FROM debian:bookworm-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY main.cpp account.cpp account.h security.cpp security.h ./
RUN g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic \
    main.cpp account.cpp security.cpp -o /account_lab -lcrypto

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 libstdc++6 tzdata \
    && rm -rf /var/lib/apt/lists/*
ENV TZ=Europe/Moscow
COPY --from=build /account_lab /usr/local/bin/account_lab
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/account_lab"]
