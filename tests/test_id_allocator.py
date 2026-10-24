"""Tests for WazuhIDAllocator."""

import pytest
from sigma.backends.wazuh.id_allocator import WazuhIDAllocator
from sigma.backends.wazuh.errors import WazuhIDCollisionError


def test_id_allocator_deterministic():
    alloc1 = WazuhIDAllocator(min_id=100000, max_id=120000)
    alloc2 = WazuhIDAllocator(min_id=100000, max_id=120000)

    uuid_test = "25b16954-bf63-42d4-bb32-9c3f03b22cf3"
    sid1 = alloc1.allocate(uuid_test)
    sid2 = alloc2.allocate(uuid_test)

    assert sid1 == sid2
    assert 100000 <= sid1 <= 120000


def test_id_allocator_different_rules():
    alloc = WazuhIDAllocator(min_id=100000, max_id=120000)
    sid1 = alloc.allocate("rule-1")
    sid2 = alloc.allocate("rule-2")

    assert sid1 != sid2
    assert 100000 <= sid1 <= 120000
    assert 100000 <= sid2 <= 120000


def test_id_allocator_subrule_allocation():
    alloc = WazuhIDAllocator(min_id=100000, max_id=120000)
    parent_id = alloc.allocate("parent-rule")
    sub1 = alloc.allocate_subrule_id("parent-rule", 0)
    sub2 = alloc.allocate_subrule_id("parent-rule", 1)

    assert parent_id != sub1
    assert sub1 != sub2
    assert 100000 <= sub1 <= 120000
    assert 100000 <= sub2 <= 120000


def test_id_allocator_reset():
    alloc = WazuhIDAllocator(min_id=100000, max_id=100005)
    sid1 = alloc.allocate("rule-a")
    alloc.reset()
    assert len(alloc.allocated_sids) == 0
    sid2 = alloc.allocate("rule-a")
    assert sid1 == sid2


def test_id_allocator_invalid_bounds():
    with pytest.raises(ValueError):
        WazuhIDAllocator(min_id=100, max_id=50)
