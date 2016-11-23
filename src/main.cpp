// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#include "defines.h"
#include "nmtools.h"
#include "config.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        puts("Usage: doubletap <config>");
        return 1;
    }

    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    try {
        cfg::instance.load(argv[1]);
    } catch (const std::exception &ex) {
        puts("Unable to parse configuration file");
        puts(ex.what());
        return 1;
    }

    if (cfg::instance.m_daemon)
    {
        int f = fork();
        if (f == -1)
        {
            puts("Unable to launch a daemon.");
            return 1;
        }

        if (f)
        {
            printf("Launched a daemon (pid: %d).\n", f);
            return 0;
        }
    }

    utils::init_clock64();

    if (!cfg::instance.m_daemon)
        OLOG_ENABLE_CONSOLE(easylogger::log_level_all);

    if (!cfg::instance.m_logs.empty())
        OLOG_ENABLE_FILE(easylogger::log_level_all, cfg::instance.m_logs);

    OLOGE << "Starting up doubletap " << version_major_k << "." << version_minor_k;
    OLOGE << "(c)2016 Alexey Potakhov [alex@potahov.com]";

    utils::replace_mod_files();

    if (!utils::assign_irq_handlers())
    {
        OLOG_STOP();
        return 1;
    }

    utils::manage_interface_promisc_mode(true);
    utils::tune_interface_settings();

    if (!netmap::init()) {
        OLOG_STOP();
        return 1;
    }

    netmap::loop();
    netmap::terminate();

    OLOG_STOP();

    return 0;
}
