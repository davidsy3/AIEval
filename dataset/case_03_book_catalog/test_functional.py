import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_catalog(":memory:")
    mod.add_book(c, "The Long Winter", "Ana Cruz", 1998, "FIC")
    mod.add_book(c, "Winter Gardens", "Ana Cruz", 2004, "FIC")
    mod.add_book(c, "Bridge Design Basics", "Piet Okonjo", 2011, "TEC")
    return c


def test_search_by_title_substring(mod, conn):
    assert [b["title"] for b in mod.search_by_title(conn, "Winter")] == [
        "The Long Winter",
        "Winter Gardens",
    ]


def test_search_by_title_no_match(mod, conn):
    assert mod.search_by_title(conn, "Zeppelin") == []


def test_search_by_title_rejects_empty(mod, conn):
    with pytest.raises(ValueError):
        mod.search_by_title(conn, "   ")


def test_search_by_author(mod, conn):
    assert [b["title"] for b in mod.search_by_author(conn, "Cruz")] == [
        "The Long Winter",
        "Winter Gardens",
    ]
    assert mod.search_by_author(conn, "Okonjo")[0]["year"] == 2011


def test_shelve_moves_book(mod, conn):
    book_id = mod.add_book(conn, "Atlas of Rivers", "Lena Vos", 2019)
    mod.shelve(conn, book_id, "REF")
    assert mod.shelf_summary(conn) == {"FIC": 2, "REF": 1, "TEC": 1}
    with pytest.raises(KeyError):
        mod.shelve(conn, 9999, "REF")


def test_published_between(mod, conn):
    assert [b["year"] for b in mod.published_between(conn, 2000, 2015)] == [2004, 2011]


def test_catalog_persists_to_file(mod, tmp_path):
    path = str(tmp_path / "catalog.db")
    first = mod.open_catalog(path)
    mod.add_book(first, "Quiet Harbour", "Rui Sena", 1987, "FIC")
    first.close()
    assert len(mod.search_by_title(mod.open_catalog(path), "Harbour")) == 1
