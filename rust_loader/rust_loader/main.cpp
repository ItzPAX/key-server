#include "includes.hpp"
#include "ui.h"
#include "hwid.hpp"

int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	srand(time(0));
	
	user_data::hwid = hwid::calc_hwid();
	
	ui::instance().init();
	while (true)
	{
		ui::instance().render();
	}

	return 0;
}