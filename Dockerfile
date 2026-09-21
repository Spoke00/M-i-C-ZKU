FROM gcc:latest

WORKDIR /app

COPY task1.cpp task2.cpp ./

RUN g++ -o task1 task1.cpp -std=c++17
RUN g++ -o task2 task2.cpp -std=c++17

CMD ["./task1"]