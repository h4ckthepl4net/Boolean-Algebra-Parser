
#include <vector>
#include <array>
#include <string>
#include <map>

enum class BooleanOperationType {
	NOT,
	AND,
	OR,
	IMPLICATION,
	EQUIVALENCE,
	XOR,
	NAND,
	NOR,
};

static std::vector<std::string> operationSymbols = {
	"!",
	"&",
	"V",
	"->",
	"<->",
	"+",
	"/|\\",
	"\\|/"
};

class IBooleanOperation {
public:
	IBooleanOperation() {}
	virtual bool calculate() = 0;
	virtual std::string toString(bool = true) = 0;
};

class Value : public IBooleanOperation {
protected:
	bool value;
public:
	Value(bool val) : value(val) {};
	bool calculate() {
		return value;
	}
	std::string toString(bool) {
		return value ? "1" : "0";
	}
	bool flip() {
		return value = !value;
	}
	bool setValue(bool val) {
		bool oldVal = value;
		value = val;
		return oldVal;
	}
	bool getValue() {
		return value;
	}
};

class Variable : public IBooleanOperation {
protected:
	std::string name;
	IBooleanOperation* value = nullptr;
public:
	Variable(std::string& name, IBooleanOperation* value = nullptr) : name(name), value(value) {}
	bool calculate() {
		if (value == nullptr) {
			throw std::exception("Variable has no value");
		}
		return value->calculate();
	}
	std::string toString(bool) {
		return name;
	}
	IBooleanOperation* setValue(IBooleanOperation* value) {
		return this->value = value;
	}
	IBooleanOperation* getValue() {
		return value;
	}
	virtual ~Variable() {
		if (value) {
			delete value;
		}
	}
};

class BooleanOperation : public IBooleanOperation {
protected:
	std::string getSymbol() {
		return operationSymbols[static_cast<unsigned int>(getType())];
	}
	virtual BooleanOperationType getType() = 0;
	bool isOperandPrecedenceHigher(IBooleanOperation* operand) {
		if (operand == nullptr) {
			throw std::exception("Operand cannot be nullptr");
		}
		BooleanOperation* booleanOperand = dynamic_cast<BooleanOperation*>(operand);
		if (booleanOperand != nullptr) {
			BooleanOperationType operandType = booleanOperand->getType();
			BooleanOperationType thisType = getType();
			unsigned int operandIndex = static_cast<unsigned int>(operandType);
			unsigned int thisIndex = static_cast<unsigned int>(thisType);
			unsigned int equivalenceId = static_cast<unsigned int>(BooleanOperationType::EQUIVALENCE);
			unsigned int operandPrecedence = operandIndex < equivalenceId ? operandIndex : equivalenceId;
			unsigned int thisPrecedence = thisIndex < equivalenceId ? thisIndex : equivalenceId;
			if (operandPrecedence <= thisPrecedence) {
				return true;
			}
		}
		return false;
	}
};

class UnaryBooleanOperation : public BooleanOperation {
protected:
	IBooleanOperation* operand;
public:
	UnaryBooleanOperation(IBooleanOperation* operand) : operand(operand) {}
	virtual IBooleanOperation* getOperand() {
		return operand;
	}
	virtual IBooleanOperation* setOperand(IBooleanOperation* operand) {
		if (operand == nullptr) {
			throw std::exception("Unary boolean operation must have operand");
		}
		IBooleanOperation* oldOperand = this->operand;
		this->operand = operand;
		return oldOperand;
	}
	virtual ~UnaryBooleanOperation() {
		delete operand;
	}
};

class Not : public UnaryBooleanOperation {
public:
	Not(IBooleanOperation* operand) : UnaryBooleanOperation(operand) {}
	bool calculate() override {
		return !operand->calculate();
	}
	std::string toString(bool) {
		return getSymbol() + operand->toString(true);
	}
	BooleanOperationType getType() {
		return BooleanOperationType::NOT;
	}
};

class BinaryBooleanOperation : public BooleanOperation {
protected:
	std::array<IBooleanOperation*, 2> operands;
public:
	BinaryBooleanOperation(IBooleanOperation* operand1, IBooleanOperation* operand2) {
		if (operand1 == nullptr || operand2 == nullptr) {
			throw std::exception("Binary boolean operation must have 2 operands");
		}
		operands[0] = operand1;
		operands[1] = operand2;
	}
	virtual IBooleanOperation* getOperand(unsigned int index) {
		return operands[index];
	}
	virtual IBooleanOperation* setOperand(unsigned int index, IBooleanOperation* operand) {
		if (operand == nullptr) {
			throw std::exception("Binary boolean operation must have 2 operands");
		}
		IBooleanOperation* oldOperand = operands[index];
		operands[index] = operand;
		return oldOperand;
	}
	virtual ~BinaryBooleanOperation() {
		delete operands[0];
		delete operands[1];
	}
};

class Implication : public BinaryBooleanOperation {
public:
	Implication (IBooleanOperation* operand1, IBooleanOperation* operand2) : BinaryBooleanOperation(operand1, operand2) {}
	bool calculate() override {
		return !operands[0]->calculate() || operands[1]->calculate();
	}
	std::string toString(bool parentheses) override {
		const bool isOperand1HighPrecedence = isOperandPrecedenceHigher(operands[0]);
		const bool isOperand2HighPrecedence = isOperandPrecedenceHigher(operands[1]);
		std::string result = parentheses ? "(" : "";
		result += operands[0]->toString(!isOperand1HighPrecedence) + " " + getSymbol() + " " + operands[1]->toString(!isOperand2HighPrecedence);
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::IMPLICATION;
	}
};

class MultiOperandBooleanOperation : public BooleanOperation {
protected:
	std::vector<IBooleanOperation*> operands;
public:
	MultiOperandBooleanOperation(std::vector<IBooleanOperation*> operands) : operands(operands) {
		if (operands.size() < 2) {
			throw std::exception("Multi operand boolean operation must have at least 2 operands");
		}
		for (IBooleanOperation* op : operands) {
			if (op == nullptr) {
				throw std::exception("Multi operand boolean operation cannot have operand equal to nullptr");
			}
		}
	}
	virtual IBooleanOperation* getOperand(unsigned int index) {
		if (index >= operands.size()) {
			throw std::exception("No operand at specified index");
		}
		return operands[index];
	}
	virtual IBooleanOperation* setOperand(unsigned int index, IBooleanOperation* operand) {
		if (operand == nullptr) {
			throw std::exception("Multi operand boolean operation must have operands");
		}
		IBooleanOperation* oldOperand = nullptr;
		if (index >= operands.size()) {
			operands.push_back(operand);
		} else {
			oldOperand = operands[index];
			operands[index] = operand;
		}
		return oldOperand;
	}
	virtual ~MultiOperandBooleanOperation() {
		for (auto operand : operands) {
			delete operand;
		}
	}
};

class Or : public MultiOperandBooleanOperation {
public:
	Or(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		for (auto operand : operands) {
			if (operand->calculate()) {
				return true;
			}
		}
		return false;
	}
	std::string toString(bool parentheses) override {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
			if (i != operands.size() - 1) {
				result += " " + getSymbol() + " ";
			}
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::OR;
	}
};

class And : public MultiOperandBooleanOperation {
public:
	And(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		for (auto operand : operands) {
			if (!operand->calculate()) {
				return false;
			}
		}
		return true;
	}
	std::string toString(bool parentheses) override {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::AND;
	}
};

class Xor : public MultiOperandBooleanOperation {
public:
	Xor(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		bool result = false;
		for (auto operand : operands) {
			result = result ^ operand->calculate();
		}
		return result;
	}
	std::string toString(bool parentheses) override {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
			if (i != operands.size() - 1) {
				result += " " + getSymbol() + " ";
			}
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::XOR;
	}
};

class Nand : public MultiOperandBooleanOperation {
public:
	Nand(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		And* andOp = new And(operands);
		return Not(andOp).calculate();
	}
	std::string toString(bool parentheses) {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
			if (i != operands.size() - 1) {
				result += " " + getSymbol() + " ";
			}
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::NAND;
	}
};

class Nor : public MultiOperandBooleanOperation {
public:
	Nor(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		Or* orOp = new Or(operands);
		return Not(orOp).calculate();
	}
	std::string toString(bool parentheses) {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
			if (i != operands.size() - 1) {
				result += " " + getSymbol() + " ";
			}
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::NOR;
	}
};

class Equivalence : public MultiOperandBooleanOperation {
public:
	Equivalence(std::vector<IBooleanOperation*>& operands) : MultiOperandBooleanOperation(operands) {}
	bool calculate() override {
		bool firstResult = operands[0]->calculate();
		for (auto operand : operands) {
			if (firstResult != operand->calculate()) {
				return false;
			}
		}
		return true;
	}
	std::string toString(bool parentheses) {
		std::string result = parentheses ? "(" : "";
		for (unsigned int i = 0; i < operands.size(); i++) {
			const bool isOperandHighPrecedence = isOperandPrecedenceHigher(operands[i]);
			result += operands[i]->toString(!isOperandHighPrecedence);
			if (i != operands.size() - 1) {
				result += " " + getSymbol() + " ";
			}
		}
		if (parentheses) {
			result += ")";
		}
		return result;
	}
	BooleanOperationType getType() {
		return BooleanOperationType::EQUIVALENCE;
	}
};

class BooleanFunctionToken {
	public:
		enum class Type {
			Unknown,
			Variable,
			Constant,
			Operator,
			LeftParentheses,
			RightParentheses
		};
		Type type;
		std::string subExpression;
		BooleanFunctionToken(std::string subExpression, Type t = Type::Unknown) : subExpression(subExpression) {
			if (t == Type::Unknown) {
				type = getType(subExpression);
			}
			else if (
				t == Type::Variable ||
				t == Type::Constant ||
				t == Type::Operator ||
				t == Type::LeftParentheses ||
				t == Type::RightParentheses
			) {
				type = t;
			}
			else {
				throw std::exception("Unknown token type");
			}
		}

		bool isParentheses() {
			return isLeftParentheses() || isRightParentheses();
		}

		bool isLeftParentheses() {
			return type == Type::LeftParentheses;
		}

		bool isRightParentheses() {
			return type == Type::RightParentheses;
		}

		static Type getType(const std::string& subExpression) {
			if (subExpression == "0" || subExpression == "1") {
				return Type::Constant;
			}
			else if (std::find(operationSymbols.begin(), operationSymbols.end(), subExpression) != operationSymbols.end()) {
				return Type::Operator;
			}
			else if (subExpression == "(") {
				return Type::LeftParentheses;
			}
			else if (subExpression == ")") {
				return Type::RightParentheses;
			}
			else if (subExpression.length() == 1 && isalpha(subExpression[0])) {
				return Type::Variable;
			}
			else {
				return Type::Unknown;
			}
		}
};

class BooleanFunction {
	static void clearTokenVector(std::vector<BooleanFunctionToken*>& tokens) {
		for (BooleanFunctionToken*& token : tokens) {
			delete token;
		}
	}

	static std::vector<BooleanFunctionToken*> tokenize(std::string expression) {
		expression.erase(std::remove(expression.begin(), expression.end(), ' '), expression.end());
		std::vector<BooleanFunctionToken*> tokens;
		try {
			std::string currentToken = "";
			for (unsigned int i = 0; i < expression.length(); i++) {
				currentToken += expression[i];
				BooleanFunctionToken::Type currentTokenType = BooleanFunctionToken::getType(currentToken);
				if (currentTokenType != BooleanFunctionToken::Type::Unknown) {
					bool areLastAndCurrentConstants = false;
					if (tokens.size() > 0) {
						auto lastToken = tokens.back();
						auto lastTokenType = lastToken->type;
						std::string notSymbol = operationSymbols[static_cast<unsigned int>(BooleanOperationType::NOT)];
						if (
							(
								(
									currentTokenType == BooleanFunctionToken::Type::Variable ||
									currentTokenType == BooleanFunctionToken::Type::LeftParentheses ||
									currentTokenType == BooleanFunctionToken::Type::Operator && currentToken == notSymbol
								) &&
								(
									lastTokenType == BooleanFunctionToken::Type::Variable ||
									lastTokenType == BooleanFunctionToken::Type::RightParentheses
								)
							)
						) {
							const unsigned int tokenIndex = static_cast<unsigned int>(BooleanOperationType::AND);
							tokens.push_back(new BooleanFunctionToken(operationSymbols[tokenIndex], BooleanFunctionToken::Type::Operator));
						}
						else if (currentTokenType == BooleanFunctionToken::Type::Constant &&
								lastTokenType == BooleanFunctionToken::Type::Constant) {
							if (currentToken == "1") {
								lastToken->subExpression = "1";
							}
							areLastAndCurrentConstants = true;
						}
					}
					if (!areLastAndCurrentConstants) {
						tokens.push_back(new BooleanFunctionToken(currentToken, currentTokenType));
					}
					currentToken = "";
				}
			}
			if (currentToken != "") {
				throw std::exception(std::string("Cannot tokenize starting from [" + currentToken + "]").c_str());
			}
		}
		catch (std::exception& e) {
			BooleanFunction::clearTokenVector(tokens);
			throw e;
		}
		return tokens;
	}


	static std::pair<IBooleanOperation*, std::map<std::string, Variable*>> parse(std::vector<BooleanFunctionToken*>& expressionTokens, std::map<std::string, Variable*> initialVariables = {}) {
		IBooleanOperation* result = nullptr;
		unsigned int parenthesesState = 0;
		std::map<std::string, Variable*> variables = initialVariables;
		std::vector<std::pair<BooleanFunctionToken*, IBooleanOperation*>> mainExpression;
		std::vector<BooleanFunctionToken*> subExpression;
		auto operationSymbolsBegin = operationSymbols.cbegin();
		auto operationSymbolsEnd = operationSymbols.cend();
		unsigned int reducedTokens = 0;
		std::multimap<unsigned int, unsigned int> operatorTokens;
		try {
			for (unsigned int i = 0; i < expressionTokens.size(); i++) {
				BooleanFunctionToken& token = *expressionTokens[i];
				if (token.isLeftParentheses()) {
					parenthesesState++;
				}
				else if (token.isRightParentheses()) {
					if (parenthesesState == 0) {
						throw std::exception("Malformed parentheses");
					}
					parenthesesState--;
					if (parenthesesState == 0) {
						std::pair<IBooleanOperation*, std::map<std::string, Variable*>> subExpressionResult = parse(subExpression, variables);
						for (std::pair<const std::string, Variable*>& var : subExpressionResult.second) {
							auto findResult = variables.find(var.first);
							if (findResult == variables.cend()) {
								variables.emplace(var);
							}
						}
						mainExpression.push_back(std::pair<BooleanFunctionToken*, IBooleanOperation*>(nullptr, subExpressionResult.first));
						reducedTokens += subExpression.size() + 2 - 1;
						subExpression.clear();
					}
					else {
						reducedTokens += 2;
					}
				}
				if (parenthesesState != 0) {
					if (!token.isParentheses()) {
						subExpression.push_back(&token);
					}
				}
				else {
					if (!token.isParentheses()) {
						std::pair<BooleanFunctionToken*, IBooleanOperation*> tokenPair;
						if (token.type == BooleanFunctionToken::Type::Variable) {
							std::string& variableName = token.subExpression;
							auto findResult = variables.find(variableName);
							if (findResult == variables.cend()) {
								variables.emplace(std::make_pair(variableName, new Variable(variableName)));
							}
							tokenPair.first = nullptr;
							tokenPair.second = variables[variableName];
						}
						else if (token.type == BooleanFunctionToken::Type::Constant) {
							tokenPair.first = nullptr;
							tokenPair.second = new Value(token.subExpression == "1");
						}
						else if (token.type == BooleanFunctionToken::Type::Operator) {
							auto findResult = std::find(operationSymbolsBegin, operationSymbolsEnd, token.subExpression);
							if (findResult == operationSymbolsEnd) {
								throw std::exception("Unknown operator");
							}
							unsigned int precendence = std::distance(operationSymbolsBegin, findResult);
							unsigned int equivalenceId = static_cast<unsigned int>(BooleanOperationType::EQUIVALENCE);
							precendence = precendence < equivalenceId ? precendence : equivalenceId;
							operatorTokens.emplace(std::make_pair(precendence, i - reducedTokens));
							tokenPair.first = &token;
							tokenPair.second = nullptr;
						}
						else {
							tokenPair.first = &token;
							tokenPair.second = nullptr;
						}
						mainExpression.push_back(tokenPair);
					}
				}
			}
			if (parenthesesState != 0) {
				throw std::exception("Malformed parentheses");
			}
			if (mainExpression.size() == 0) {
				throw std::exception("Empty expression");
			}
			for (auto it = operatorTokens.cbegin(); it != operatorTokens.cend(); ++it) {
				std::pair<unsigned int, unsigned int> operatorTokenPair = *it;
				unsigned int operatorTokenIndex = operatorTokenPair.second;
				std::pair<BooleanFunctionToken*, IBooleanOperation*>& token = mainExpression[operatorTokenIndex];
				BooleanFunctionToken* operatorToken = token.first;
				BooleanOperationType operationType = static_cast<BooleanOperationType>(std::distance(operationSymbolsBegin, std::find(operationSymbolsBegin, operationSymbolsEnd, operatorToken->subExpression)));
				unsigned int deletedTokens = 0;
				if (operationType == BooleanOperationType::NOT) {
					unsigned int operandIndex = operatorTokenIndex + 1;
					if (operandIndex >= mainExpression.size()) {
						throw std::exception(std::string("Malformed expression at [" + token.first->subExpression + "]").c_str());
					}
					std::pair<BooleanFunctionToken*, IBooleanOperation*>& operandToken = mainExpression[operandIndex];
					IBooleanOperation* operand = operandToken.second;
					if (operand == nullptr) {
						throw std::exception(std::string("Malformed expression at [" + token.first->subExpression + "]").c_str());
					}
					result = new Not(operand);
					token.second = result;
					mainExpression.erase(mainExpression.begin() + operandIndex);
					deletedTokens = 1;
				}
				else {
					unsigned int operand1Index = operatorTokenIndex - 1;
					unsigned int operand2Index = operatorTokenIndex + 1;
					if (operand1Index < 0 || operand2Index >= mainExpression.size()) {
						throw std::exception(std::string("Malformed expression at [" + token.first->subExpression + "]").c_str());
					}
					std::pair<BooleanFunctionToken*, IBooleanOperation*>& operand1Token = mainExpression[operand1Index];
					std::pair<BooleanFunctionToken*, IBooleanOperation*>& operand2Token = mainExpression[operand2Index];
					IBooleanOperation* operand1 = operand1Token.second;
					IBooleanOperation* operand2 = operand2Token.second;
					if (operand1 == nullptr || operand2 == nullptr) {
						throw std::exception(std::string("Malformed expression at [" + token.first->subExpression + "]").c_str());
					}

					std::vector<IBooleanOperation*> operands = { operand1, operand2 };
					switch (operationType) {
					case BooleanOperationType::AND:
						result = new And(operands);
						break;
					case BooleanOperationType::OR:
						result = new Or(operands);
						break;
					case BooleanOperationType::XOR:
						result = new Xor(operands);
						break;
					case BooleanOperationType::NAND:
						result = new Nand(operands);
						break;
					case BooleanOperationType::NOR:
						result = new Nor(operands);
						break;
					case BooleanOperationType::IMPLICATION:
						result = new Implication(operands[0], operands[1]);
						break;
					case BooleanOperationType::EQUIVALENCE:
						result = new Equivalence(operands);
						break;
					default:
						throw std::exception("Unknown operation type");
						break;
					}

					token.second = result;

					mainExpression.erase(mainExpression.begin() + operand1Index);
					mainExpression.erase(mainExpression.begin() + operand2Index - 1);

					deletedTokens = 2;
				}
				for (auto& token : operatorTokens) {
					if (token.second > operatorTokenIndex) {
						token.second -= deletedTokens;
					}
				}
			}
		}
		catch (std::exception& e) {
			for (auto& token : mainExpression) {
				if (token.second) {
					delete token.second;
					token.second = nullptr;
				}
			}
			variables.clear();
			throw e;
		}
		return std::make_pair(result, variables);
	}

	IBooleanOperation* expression = nullptr;
	std::vector<Value*> variableValues;
	std::map<std::string, Variable*> variables;
public:
	enum class FunctionNormalForm {
		CNF, // conjuctive normal form
		DNF, // disjunctive normal form
		ANF, // Zhegalkin polynomial or algebraic normal form
	};
	typedef std::vector<std::string> InputNames;
	typedef std::vector<bool> InputValues;
	typedef std::vector<InputValues> Inputs;
	typedef std::vector<bool> TruthTableRow;
	typedef std::vector<TruthTableRow> TruthTable;
	typedef std::tuple<InputNames, TruthTable> TruthTableWithInputNames;
	typedef std::vector<bool> Outputs;
	typedef std::vector<std::vector<std::tuple<int, int>>> InputSetPairs;
	BooleanFunction() {}
	BooleanFunction(const std::string& expression) {
		this->parseFromExpression(expression);
	}

	bool isValid() {
		return !!expression;
	}

	void parseFromExpression(const std::string& exp) {
		std::vector<BooleanFunctionToken*> tokens = tokenize(exp);
		std::pair<IBooleanOperation*, std::map<std::string, Variable*>> result = parse(tokens);
		clearTokenVector(tokens);
		this->expression = result.first;
		this->variables = result.second;
		std::vector<Value*> variableValues;
		for (auto& variable : variables) {
			Variable* var = variable.second;
			Value* val = new Value(false);
			var->setValue(val);
			variableValues.push_back(val);
		}
		this->variableValues = variableValues;
	}

	bool evaluate() {
		if (!expression) {
			throw std::exception("Cannot calculate invalid expression");
		}
		return expression->calculate();
	}

	std::string toString() {
		if (!expression) {
			throw std::exception("Cannot convert invalid expression to string");
		}
		return expression->toString(false);
	}

	Inputs getInputs() {
		if (!expression) {
			throw std::exception("Cannot get inputs of invalid expression");
		}
		const unsigned int variablesCount = variables.size();
		const unsigned int rowsCount = pow(2, variablesCount);
		Inputs result;
		result.reserve(rowsCount);
		for (unsigned int i = 0; i < rowsCount; i++) {
			InputValues row;
			row.reserve(variablesCount);
			row.resize(variablesCount);
			for (unsigned int j = 0; j < variablesCount; j++) {
				row[variablesCount - j - 1] = (i >> j) & 1;
			}
			result.push_back(row);
		}
		return result;
	}

	Outputs getOuputs(bool resetVariables = true) {
		if (!expression) {
			throw std::exception("Cannot get truth table of invalid expression");
		}
		const unsigned int variablesCount = variables.size();
		const unsigned int rowsCount = pow(2, variablesCount);
		std::vector<bool> result;
		result.reserve(rowsCount);
		for (unsigned int i = 0; i < rowsCount; i++) {
			for (unsigned int j = 0; j < variablesCount; j++) {
				variableValues[variablesCount - j - 1]->setValue((i >> j) & 1);
			}
			result.push_back(evaluate());
		}
		if (resetVariables) {
			for (unsigned int i = 0; i < variablesCount; i++) {
				variableValues[i]->setValue(false);
			}
		}
		return result;
	}

	TruthTable getTruthTable() {
		if (!expression) {
			throw std::exception("Cannot get truth table of invalid expression");
		}
		const unsigned int variablesCount = variables.size();
		const unsigned int rowsCount = pow(2, variablesCount);
		std::vector<std::vector<bool>> result;
		result.reserve(rowsCount);
		for (unsigned int i = 0; i < rowsCount; i++) {
			std::vector<bool> row;
			row.reserve(variablesCount + 1);
			row.resize(variablesCount);
			for (unsigned int j = 0; j < variablesCount; j++) {
				bool variableValue = (i >> j) & 1;
				unsigned int variableIndex = variablesCount - j - 1;
				row[variableIndex] = variableValue;
				variableValues[variableIndex]->setValue(variableValue);
			}
			row.push_back(evaluate());
			result.push_back(row);
		}
		for (unsigned int i = 0; i < variablesCount; i++) {
			variableValues[i]->setValue(false);
		}
		return result;
	}

	InputNames getVariableNames() {
		std::vector<std::string> result;
		for (auto& variable : variables) {
			result.push_back(variable.first);
		}
		return result;
	}

	std::string getDisunctiveNormalForm() {
		InputNames inputNames = getVariableNames();
		TruthTable truthTable = getTruthTable();
		std::string result = "";
		auto lastTrueRow = std::find_if(truthTable.crbegin(), truthTable.crend(), [](const TruthTableRow& row) {
			return row.back();
		});
		const unsigned int lastTrueOutput = std::distance(lastTrueRow, truthTable.crend()) - 1;
		for (unsigned int i = 0; i < truthTable.size(); i++) {
			auto currentRow = truthTable[i];
			if (currentRow.back()) {
				for (unsigned int j = 0; j < inputNames.size(); j++) {
					if (!currentRow[j]) {
						result += "!";
					}
					result += inputNames[j];
				}
				if (i != lastTrueOutput) {
					result += " V ";
				}
			}
		}
		return result;
	}

	std::string getConjunctiveNormalForm() {
		InputNames inputNames = getVariableNames();
		TruthTable truthTable = getTruthTable();
		std::string result = "";
		auto lastFalseRow = std::find_if(truthTable.crbegin(), truthTable.crend(), [](const TruthTableRow& row) {
			return !row.back();
		});
		const unsigned int lastFalseOutput = std::distance(lastFalseRow, truthTable.crend()) - 1;
		for (unsigned int i = 0; i < truthTable.size(); i++) {
			auto currentRow = truthTable[i];
			if (!currentRow.back()) {
				result += "(";
				for (unsigned int j = 0; j < inputNames.size(); j++) {
					if (currentRow[j]) {
						result += "!";
					}
					result += inputNames[j];
					if (j != inputNames.size() - 1) {
						result += " V ";
					}
				}
				result += ")";
				if (i != lastFalseOutput) {
					result += " & ";
				}
			}
		}
		return result;
	}

	std::string getAlgebraicNormalForm() {
		InputNames inputNames = getVariableNames();
		TruthTable truthTable = getTruthTable();
		std::vector<std::vector<bool>> pascalTable;
		const unsigned int tableColumns = pow(2, inputNames.size());
		const unsigned int tableRows = inputNames.size() + 1;
		pascalTable.reserve(tableRows);
		std::vector<bool> firstRow(tableColumns, false);
		std::vector<bool> test = {1, 0, 1,1,0,0,1,0};
		for (unsigned int i = 0; i < tableColumns; i++) {
			TruthTableRow& currentRow = truthTable[i];
			firstRow[i] = currentRow.back();
		}
		pascalTable.push_back(firstRow);
		unsigned int blockSize = 2;
		for (unsigned int i = 1; i < tableRows; i++) {
			std::vector<bool> currentRow(tableColumns, false);
			for (unsigned int j = 0; j < tableColumns; j++) {
				unsigned int itemIndex = j % blockSize;
				unsigned int halfOfBlock = blockSize / 2;
				if (itemIndex < halfOfBlock) {
					currentRow[j] = pascalTable[i - 1][j];
				}
				else {
					unsigned int fullBlocks = j / halfOfBlock;
					unsigned int blockItemIndex = j % halfOfBlock;
					unsigned int previousBlock = fullBlocks - 1;
					unsigned int previousBlockStartIndex = previousBlock * halfOfBlock;
					currentRow[j] = pascalTable[i - 1][j] ^ pascalTable[i - 1][previousBlockStartIndex + blockItemIndex];
				}
			}
			pascalTable.push_back(currentRow);
			blockSize *= 2;
		}
		std::string result = "";
		std::vector<bool>& pascalTableResultRow = pascalTable.back();
		unsigned int lastTrueColumnIndex = std::distance(std::find(pascalTableResultRow.crbegin(), pascalTableResultRow.crend(), true), pascalTableResultRow.crend()) - 1;
		for (unsigned int i = 0; i < tableColumns; i++) {
			if (pascalTableResultRow[i]) {
				TruthTableRow& currentRow = truthTable[i];
				bool nothingInRow = true;
				for (unsigned int j = 0; j < inputNames.size(); j++) {
					if (currentRow[j]) {
						nothingInRow = false;
						result += inputNames[j];
					}
				}
				if (nothingInRow) {
					result += "1";
				}
				if (i != lastTrueColumnIndex) {
					result += " + ";
				}
			}
		}
		return result;
	}

	std::string getNormalForm(FunctionNormalForm type) {
		switch (type)
		{
		case FunctionNormalForm::CNF:
			return getConjunctiveNormalForm();
			break;
		case FunctionNormalForm::DNF:
			return getDisunctiveNormalForm();
			break;
		case FunctionNormalForm::ANF:
			return getAlgebraicNormalForm();
			break;
		}
		throw std::exception("Unknown normal form type");
	}

	InputSetPairs getInputSetPairsDifferingByOneVariable() {
		InputNames inputNames = getVariableNames();
		Inputs inputs = getInputs();
		InputSetPairs inputPairs;
		for (unsigned int i = 0; i < inputNames.size(); i++) {
			std::vector<std::tuple<int, int>> inputPairsForCurrentInput;
			for (unsigned int j = 0; j < inputs.size(); j++) {
				InputValues& currentInputSet = inputs[j];
				for (unsigned int k = j + 1; k < inputs.size(); k++) {
					InputValues& nextInputSet = inputs[k];
					if (currentInputSet[i] == nextInputSet[i]) {
						continue;
					}
					unsigned int differentBitsCount = 0;
					for (unsigned int l = 0; l < inputNames.size(); l++) {
						if (currentInputSet[l] != nextInputSet[l]) {
							differentBitsCount++;
						}
					}
					if (differentBitsCount == 1) {
						inputPairsForCurrentInput.push_back(std::make_tuple(j, k));
					}
				}
			}
			inputPairs.push_back(inputPairsForCurrentInput);
		}
		return inputPairs;
	}

	std::vector<bool> getUsedInputs() {
		unsigned int inputsCount = variables.size();
		Outputs outputs = getOuputs(false);
		InputSetPairs pairsToCheck = getInputSetPairsDifferingByOneVariable();
		std::vector<bool> isInputUsed(inputsCount, 0);
		for (unsigned int i = 0; i < pairsToCheck.size(); i++) {
			std::vector<std::tuple<int, int>>& currentInputPairs = pairsToCheck[i];
			for (unsigned int j = 0; j < currentInputPairs.size(); j++) {
				std::tuple<int, int>& currentInputPair = currentInputPairs[j];
				bool firstRowOutput = outputs[std::get<0>(currentInputPair)];
				bool secondRowOutput = outputs[std::get<1>(currentInputPair)];
				if (firstRowOutput != secondRowOutput) {
					isInputUsed[i] = true;
					break;
				}
			}
		}
		return isInputUsed;
	}

	TruthTable getFilteredTruthTable() {
		TruthTable functionTruthTable = getTruthTable();
		InputNames inputNames = getVariableNames();
		std::vector<bool> usedInputs = getUsedInputs();
		TruthTable truthTableRows;
		for (unsigned int i = 0; i < functionTruthTable.size(); i++) {
			InputValues& currentInputSet = functionTruthTable[i];
			std::vector<bool> currentInputSetWithoutFictiveVariables;
			bool addRow = true;
			for (unsigned int j = 0; j < inputNames.size(); j++) {
				if (usedInputs[j]) {
					currentInputSetWithoutFictiveVariables.push_back(currentInputSet[j]);
				}
				else if (currentInputSet[j]) {
					addRow = false;
					break;
				}
			}
			currentInputSetWithoutFictiveVariables.push_back(functionTruthTable[i].back());
			if (addRow) {
				truthTableRows.push_back(currentInputSetWithoutFictiveVariables);
			}
		}
		return truthTableRows;
	}

	TruthTableWithInputNames getFilteredTruthTableWithInputNames() {
		TruthTable truthTable = getFilteredTruthTable();
		InputNames inputNames = getVariableNames();
		std::vector<bool> usedInputs = getUsedInputs();
		InputNames filteredInputNames;
		for (unsigned int i = 0; i < inputNames.size(); i++) {
			if (usedInputs[i]) {
				filteredInputNames.push_back(inputNames[i]);
			}
		}
		return std::make_tuple(filteredInputNames, truthTable);
	}

	~BooleanFunction() {
		variables.clear();
		delete expression;
	}
};