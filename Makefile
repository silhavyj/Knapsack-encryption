TARGET = knapsack 
SUBMIT_FILE = BIT_ukol4_jakub_silhavy.zip
FILES_TO_SUBMIT = src data keys Makefile README.md
CCX    = g++
FLAGS  = -Wall -O2 -std=c++17 -pedantic-errors -Wextra -Werror
SRC    = src
BIN    = bin
SOURCE = $(wildcard $(SRC)/*.cpp)
OBJECT = $(patsubst %,$(BIN)/%, $(notdir $(SOURCE:.cpp=.o)))

$(TARGET) : $(OBJECT)
	$(CCX) $(FLAGS) -o $@ $^

$(BIN)/%.o : $(SRC)/%.cpp
	@mkdir -p $(BIN)
	$(CCX) $(FLAGS) -c $< -o $@

.PHONY submit:
submit:
	zip -r $(SUBMIT_FILE) $(FILES_TO_SUBMIT)

.PHONY clean:
clean:
	rm -rf $(BIN) $(TARGET)