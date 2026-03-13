FROM gcc:13

WORKDIR /app

COPY main.cpp .

RUN g++ -std=c++17 -O2 -o residence main.cpp -lpthread

EXPOSE 3000

CMD ["./residence", "3000", "residence_db.json"]
