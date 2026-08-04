from dataclasses import dataclass


class SourceError(ValueError):
    """Raised when a firmware source is not explicitly allowlisted."""


@dataclass(frozen=True)
class SourceSpec:
    model: str
    region: str
    version: str
    filename: str
    advertised_size: int
    page_url: str


_SOURCES = {
    "a6400-tw-v2.00": SourceSpec(
        model="ILCE-6400",
        region="TW",
        version="2.00",
        filename="Update_ILCE6400V200.exe",
        advertised_size=314_230_712,
        page_url=(
            "https://www.sony.com.tw/zh/electronics/support/"
            "e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145"
        ),
    ),
    "a6700-tw-v2.00": SourceSpec(
        model="ILCE-6700",
        region="TW",
        version="2.00",
        filename="BODYDATA.DAT",
        advertised_size=1_024_017_848,
        page_url=(
            "https://www.sony.com.tw/zh/electronics/support/"
            "e-mount-body-ilce-6000-series/ilce-6700/software/00298440"
        ),
    ),
}


def get_source(key: str) -> SourceSpec:
    try:
        return _SOURCES[key]
    except KeyError as error:
        raise SourceError("Firmware source is not allowlisted") from error
