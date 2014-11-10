#ifndef MOCK_NAMED_PIPE_HH
#define MOCK_NAMED_PIPE_HH

#include "named_pipe.h"
#include "mock_expectation.hh"

class MockNamedPipe
{
  public:
    MockNamedPipe(const MockNamedPipe &) = delete;
    MockNamedPipe &operator=(const MockNamedPipe &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    bool ignore_all_;

    explicit MockNamedPipe();
    ~MockNamedPipe();

    void init();
    void check() const;

    void expect_fifo_create_and_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_close_and_delete(int *fd, const char *devname);
    void expect_fifo_close(int *fd);
    void expect_fifo_reopen(bool ret, int *fd, const char *devname, bool write_not_read);

    typedef int (*fifo_write_from_buffer_callback_t)(const uint8_t *src, size_t count, int fd);
    void expect_fifo_write_from_buffer(int ret, const uint8_t *src, size_t count, int fd);
    void expect_fifo_write_from_buffer_callback(fifo_write_from_buffer_callback_t fn);

    typedef int (*fifo_try_read_to_buffer_callback_t)(uint8_t *dest, size_t count, size_t *add_bytes_read, int fd);
    void expect_fifo_try_read_to_buffer(int ret, uint8_t *dest, size_t count,
                                        size_t *add_bytes_read, int fd);
    void expect_fifo_try_read_to_buffer_callback(fifo_try_read_to_buffer_callback_t fn);
};

extern MockNamedPipe *mock_named_pipe_singleton;

#endif /* !MOCK_NAMED_PIPE_HH */
