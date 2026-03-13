FROM gcc:13

RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY main.cpp .

RUN g++ -std=c++17 -O2 -o residence main.cpp -lpthread -lpq -I/usr/include/postgresql

EXPOSE 3000

CMD ["./residence", "3000"]
