// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include "defines.h"

#define OLOG(level) \
        if (!(level & easylogger::logger::get_current_level())) { } else \
            for (easylogger::record t_rec(level), *t_ptr = NULL; !t_ptr; t_ptr = &t_rec) \
                t_rec.m_os

#define OLOGE OLOG(easylogger::log_level_event)
#define OLOGM OLOG(easylogger::log_level_message)
#define OLOGX OLOG(easylogger::log_level_error)
#define OLOGH OLOG(easylogger::log_level_hint)

#define OLOG_ENABLE_CONSOLE(level) easylogger::logger::get_logger()->set_console_log_level(level)
#define OLOG_ENABLE_FILE(level, name) easylogger::logger::get_logger()->set_file_log_level(level, name)

namespace easylogger
{
    enum log_level
    {
        log_level_none      = 0,
        log_level_event     = 1,
        log_level_message   = 2,
        log_level_error     = 4,
        log_level_hint      = 8,
        log_level_all       = 15
    };

    class logger;

    class record
    {
        friend class logger;
    public:
        record(int v_level) : m_level(v_level) {}
        ~record();

        std::ostringstream m_os;
    private:
        int m_level;

        record(const record &v_record);
        record &operator=(const record &v_record);
    };

    template <typename T>
    inline record& operator <<(record& v_log, T const & v_value) {
        v_log.m_os << v_value;
        return v_log;
    }

    class logger
    {
    public:
        ~logger();

        static void shutdown();

        static logger *get_logger();

        static inline int get_current_level()
        {
            return m_console_level | m_file_level;
        }

        void set_console_log_level(int v_level);
        void set_file_log_level(int v_level, const std::string &v_path);
        void flush_record(record *v_record);
    private:
        logger();

        std::string _pack_parameters(uint32_t v_id, uint32_t v_number, const std::string &v_line = std::string());
        bool _unpack_parameters(const std::string &v_data, uint32_t &v_id, uint32_t &v_number, std::string &v_line);
        std::string _get_log_file_name();
        void _flush_current_file();
        void _thread_processor();

        std::atomic_bool m_stop_signal;

        static std::atomic<int> m_console_level;
        static std::atomic<int> m_file_level;

        std::string m_file_path;
        std::string m_file_cache;

        std::thread m_thread;

        std::mutex feed_mutex;
        std::deque <std::pair<int, std::string>> feed_records;
        char __output_buffer[maximum_log_line_size_k];

        logger(const logger &v_record);
        logger &operator=(const logger &v_record);
    };
}

#define OLOG_STOP easylogger::logger::shutdown
