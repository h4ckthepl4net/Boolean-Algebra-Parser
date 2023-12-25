// Boolean Algebra.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <vector>
#include <array>
#include <math.h>
#include <tuple>
#include "Boolean Parser.cpp"

void printTruthTable(BooleanFunction::InputNames inputs, BooleanFunction::TruthTable truthTable) {
	const unsigned int inputsCount = static_cast<int>(inputs.size());
	const unsigned int rowsCount = pow(2, inputsCount);
	if (rowsCount != truthTable.size()) {
		throw std::exception("Invalid truth table");
	}
	std::cout << " N |";
	for (unsigned int i = 0; i < inputsCount; i++) {
		std::cout << " " << inputs[i];
	}
	std::cout << " | F\n";
	std::cout << "---|";
	for (unsigned int i = 0; i < inputsCount; i++) {
		std::cout << "--";
	}
	std::cout << "-|---\n";
	for (unsigned int i = 0; i < rowsCount; i++) {
		std::cout << " " << i << " |";
		for (unsigned int j = 0; j < inputs.size(); j++) {
			std::cout << " " << truthTable[i][j];
		}
		std::cout << " | " << truthTable[i].back() << "\n";
	}
}

int main()
{
	std::cout << "===========================" << std::endl << std::endl;
	std::cout << "Boolean Algebra" << std::endl << std::endl;
	std::cout << "===========================" << std::endl << std::endl;
	std::cout << "Supported operations: " << std::endl;
	std::cout << "  -  !  - not" << std::endl;
	std::cout << "  -  &  - and" << std::endl;
	std::cout << "  -  V  - or" << std::endl;
	std::cout << "  -  -> - implication" << std::endl;
	std::cout << "  - <-> - equality" << std::endl;
	std::cout << "  -  +  - xor" << std::endl;
	std::cout << "  - /|\\ - shefer stroke (nand)" << std::endl;
	std::cout << "  - \\|/ - pierce arrow (nor)" << std::endl << std::endl;
	std::cout << "Expression implicit rules: " << std::endl;
	std::cout << "  - Absence of any operator between variables and parentheses will be treated as [&] (and)" << std::endl;
	std::cout << "  - Collection of literals [1, 0] (ex. 111, 101, 000) will be treated as a single literal" << std::endl;
	std::cout << "  - Any literal containing all zeroes will be treated as [0], otherwise [1]" << std::endl << std::endl;


	BooleanFunction function;
	while (!function.isValid()) {
		std::cout << "---------------------------" << std::endl << std::endl;
		std::cout << "Please enter your boolean function: ";
		std::string exp;
		std::getline(std::cin, exp);
		std::cout << std::endl;
		try {
			function.parseFromExpression(exp);
		}
		catch (std::exception& e) {
			std::cout << "[Boolean function parse failed]: " << e.what() << std::endl << std::endl;
			continue;
		}
	}
	std::cout << "---------------------------" << std::endl << std::endl;
	std::cout << "Boolean function parsed successfully" << std::endl << std::endl;

	std::cout << "Boolean function is: " << function.toString() << std::endl << std::endl;

	std::cout << "---------------------------" << std::endl << std::endl;

	std::cout << "Thruth table" << std::endl;
	std::cout << "===========================" << std::endl;
	auto inputNames = function.getVariableNames();
	auto truthTable = function.getTruthTable();
	printTruthTable(inputNames, truthTable);
	std::cout << std::endl;

	std::cout << "Thruth table without fictive variables" << std::endl;
	std::cout << "===========================" << std::endl;
	auto filteredTruthTable = function.getFilteredTruthTableWithInputNames();
	printTruthTable(std::get<0>(filteredTruthTable), std::get<1>(filteredTruthTable));
	std::cout << std::endl;
	
	std::cout << "Disjunctive normal form" << std::endl;
	std::cout << "===========================" << std::endl;
	std::cout << function.getDisunctiveNormalForm() << std::endl;
	std::cout << std::endl;

	std::cout << "Conjunctive normal form" << std::endl;
	std::cout << "===========================" << std::endl;
	std::cout << function.getConjunctiveNormalForm() << std::endl;
	std::cout << std::endl;

	std::cout << "Algebraic normal form (Zhegalkin polynomial)" << std::endl;
	std::cout << "===========================" << std::endl;
	std::cout << function.getAlgebraicNormalForm() << std::endl;
	std::cout << std::endl;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
