// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#include "log.h"
#include "utils.h"

using namespace easylogger;

static const int32_t _easylogger_int_file_k = 1;
static const int32_t _easylogger_int_console_k = 2;

std::shared_ptr<logger> _g_logger;

std::atomic<int> logger::m_console_level(log_level_none);
std::atomic<int> logger::m_file_level(log_level_none);

logger *logger::get_logger()
{
    struct logger_facade : public logger {};

    logger *l = _g_logger.get();
    if (l == nullptr) {
        _g_logger = std::make_shared<logger_facade>();
        return _g_logger.get();
    } else
        return l;
}

record::~record()
{
    logger::get_logger()->flush_record(this);
}

logger::logger()
{
    m_stop_signal = false;
    m_thread = std::thread(&logger::_thread_processor, this);
}

void logger::flush_record(record *v_record)
{
    if (v_record->m_level)
    {
        auto now = std::chrono::system_clock::now();
        time_t now_time_t = std::chrono::system_clock::to_time_t(now);
        auto cut_one = std::chrono::system_clock::from_time_t(now_time_t);
        
        int milliseconds;

        if (now > cut_one)
            milliseconds = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - cut_one).count());
        else
            milliseconds = 1000 - static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(cut_one - now).count());

        tm local_tm;
        localtime_r(&now_time_t, &local_tm);

        int hours        = local_tm.tm_hour;
        int minutes      = local_tm.tm_min;
        int seconds      = local_tm.tm_sec;

        {
            std::lock_guard<std::mutex> lk(feed_mutex);
            // using single buffer under the queue lock
            snprintf(__output_buffer, maximum_log_line_size_k, "[%02d:%02d:%02d.%04d] %s", hours, minutes, seconds, milliseconds, v_record->m_os.str().c_str());
            feed_records.push_back(std::make_pair(v_record->m_level, std::string(__output_buffer)));
        }
    }
}

logger::~logger()
{
    m_stop_signal = true;
    m_thread.join();
}

void logger::shutdown()
{
    if (_g_logger.get() != nullptr)
    {
        _g_logger.reset();
    }
}

std::string logger::_pack_parameters(uint32_t v_id, uint32_t v_number, const std::string &v_line /* = std::string() */)
{
    std::string result;
    result.append((const char *)&v_id, sizeof(uint32_t));
    result.append((const char *)&v_number, sizeof(uint32_t));
    result.append(v_line);
    return result;
}

bool logger::_unpack_parameters(const std::string &v_data, uint32_t &v_id, uint32_t &v_number, std::string &v_line)
{
    if (v_data.size() < (sizeof(uint32_t) * 2))
        return false;

    v_id = *((uint32_t *)v_data.data());
    v_number = *((uint32_t *)(v_data.data() + sizeof(uint32_t)));

    if (v_data.size() == (sizeof(uint32_t) * 2))
        return true;

    v_line.append(v_data.data() + (sizeof(uint32_t) * 2), v_data.size() - (sizeof(uint32_t) * 2));
    return true;
}

void logger::set_file_log_level(int v_level, const std::string &v_path)
{
    std::string path = std::string(v_path);
    if (!path.empty()) {
        if (path[path.length() - 1] != '/' && path[path.length() - 1] != '\\') {
                path.append("/");
        }
    }

    uint32_t t_level;

    if (path.empty())
        t_level = log_level_none;
    else
        t_level = static_cast<uint32_t>(v_level);

    {
        std::lock_guard<std::mutex> lk(feed_mutex);
        feed_records.push_back(std::make_pair(0, _pack_parameters(_easylogger_int_file_k, t_level, path)));
    }

    m_file_level = t_level;
}

void logger::set_console_log_level(int v_level)
{
    {
        std::lock_guard<std::mutex> lk(feed_mutex);
        feed_records.push_back(std::make_pair(0, _pack_parameters(_easylogger_int_console_k, static_cast<uint32_t>(v_level))));
    }

    m_console_level = v_level;
}

std::string logger::_get_log_file_name()
{
    time_t now = time(nullptr);
    tm _tm;
    localtime_r(&now, &_tm);

    char mbstr[20];
    if (!std::strftime(mbstr, 20, "%Y%m%d.log", &_tm))
        return std::string();
    else
        return std::string(mbstr);
}

void logger::_flush_current_file()
{
    std::string current_file_name = m_file_path + _get_log_file_name();
    std::ofstream file(current_file_name.c_str(), std::ios::out | std::ios::app | std::ios::binary);
    if (file)
    {
        file << m_file_cache;
    }

    m_file_cache.clear();
}

void logger::_thread_processor()
{
    uint64_t file_flush_clock = 0ULL;

    int file_local_level = log_level_none;
    int console_local_level = log_level_none;

    while (1)
    {
        std::deque<std::pair<int, std::string>> tmp_records;
        {
            std::lock_guard<std::mutex> lk(feed_mutex);
            tmp_records.swap(feed_records);
        }

        for (auto & it : tmp_records)
        {
            if (!it.first)
            {
                // got control message wrapped in a packet
                uint32_t v_id, v_level;
                std::string v_path;
                if (_unpack_parameters(it.second, v_id, v_level, v_path))
                {
                    switch (v_id)
                    {
                    case _easylogger_int_file_k:
                        {
                            if (!m_file_cache.empty())
                                _flush_current_file();

                            m_file_path = v_path;
                            file_flush_clock = 0;
                            file_local_level = v_level;
                        } break;
                    case _easylogger_int_console_k:
                        {
                            console_local_level = v_level;
                        } break;
                    }
                }
            } else {
                if ( it.first & console_local_level )
                    std::cout << it.second << std::endl;

                if ( it.first & file_local_level )
                {
                    m_file_cache.append(it.second);
                    m_file_cache.append("\n");
                }
            }
        }

        if (!m_file_cache.empty())
        {
            uint64_t current_clock = utils::clock64();
            if (file_flush_clock < current_clock)
            {
                _flush_current_file();
                file_flush_clock = current_clock + log_flush_timeout_k;
            }
        }

        if (m_stop_signal)
        {
            if (!m_file_cache.empty())
                _flush_current_file();

            break;
        }

        std::this_thread::sleep_for( std::chrono::milliseconds(log_handler_frequency_k) );
    }
}
