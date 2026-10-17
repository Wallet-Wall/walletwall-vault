"""Independent cross-check of the archive census with Python's stdlib tarfile (read-only, never extracts).

Usage: python -I tarfile_census.py <archive.tar.gz>
Prints JSON: one record per member (name, type, size, mode, uid, gid, uname, gname, mtime, pax keys, data sha256).
"""
import hashlib
import json
import sys
import tarfile

TYPES = {
    tarfile.REGTYPE: "0", tarfile.AREGTYPE: "0", tarfile.LNKTYPE: "1", tarfile.SYMTYPE: "2",
    tarfile.CHRTYPE: "3", tarfile.BLKTYPE: "4", tarfile.DIRTYPE: "5", tarfile.FIFOTYPE: "6",
    tarfile.CONTTYPE: "7",
}


def main(path):
    raw = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            raw.update(chunk)
    out = []
    with tarfile.open(path, mode="r:gz") as tf:
        for m in tf:
            h = hashlib.sha256()
            if m.isreg():
                src = tf.extractfile(m)
                for chunk in iter(lambda: src.read(1 << 22), b""):
                    h.update(chunk)
            out.append({
                "name": m.name,
                "typeflag": TYPES.get(m.type, m.type.decode("latin1")),
                "size": m.size,
                "mode": format(m.mode, "04o"),
                "uid": m.uid,
                "gid": m.gid,
                "uname": m.uname,
                "gname": m.gname,
                "mtime": int(m.mtime),
                "linkname": m.linkname,
                "paxKeys": sorted(m.pax_headers.keys()),
                "dataSha256": h.hexdigest(),
            })
    print(json.dumps({"archiveSha256": raw.hexdigest(), "members": out}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
