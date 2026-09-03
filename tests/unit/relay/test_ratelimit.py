from relay.auth.ratelimit import SlidingWindowLimiter


def test_blocks_after_limit_within_window_and_frees_after():
    lim = SlidingWindowLimiter(limit=3, window_s=60)
    for _ in range(3):
        lim.record("ip", now=100.0)
    assert lim.is_blocked("ip", now=101.0)
    assert not lim.is_blocked("other", now=101.0)
    assert not lim.is_blocked("ip", now=161.0)
