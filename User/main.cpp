#include "imports.h"

auto main() -> const int {
	auto process = utils::getprocessid(L"notepad.exe");

	printf("processid: %i\n", process);

	if (process != 0)
	{
		driver.initdriver(process);
		auto base = driver.base();
		printf("base: 0x%p\n", base);
	}

	getchar();
	return 0;
}
