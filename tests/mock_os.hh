#ifndef MOCK_OS_HH
#define MOCK_OS_HH

#include "os.h"
#include "mock_expectation.hh"

class MockOs
{
  public:
    MockOs(const MockOs &) = delete;
    MockOs &operator=(const MockOs &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockOs();
    ~MockOs();

    void init();
    void check() const;

    typedef int (*os_write_from_buffer_callback_t)(const void *src, size_t count, int fd);
    void expect_os_write_from_buffer(int ret, const void *src, size_t count, int fd);
    void expect_os_write_from_buffer_callback(os_write_from_buffer_callback_t fn);

    typedef int (*os_try_read_to_buffer_callback_t)(void *dest, size_t count, size_t *add_bytes_read, int fd);
    void expect_os_try_read_to_buffer(int ret, void *dest, size_t count,
                                      size_t *add_bytes_read, int fd);
    void expect_os_try_read_to_buffer_callback(os_try_read_to_buffer_callback_t fn);

    void expect_os_abort(void);
};

extern MockOs *mock_os_singleton;

#endif /* !MOCK_OS_HH */
