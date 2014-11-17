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

    explicit MockNamedPipe();
    ~MockNamedPipe();

    void init();
    void check() const;

    void expect_fifo_create_and_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_close_and_delete(int *fd, const char *devname);
    void expect_fifo_close(int *fd);
    void expect_fifo_reopen(bool ret, int *fd, const char *devname, bool write_not_read);
};

extern MockNamedPipe *mock_named_pipe_singleton;

#endif /* !MOCK_NAMED_PIPE_HH */
