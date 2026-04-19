import importlib.machinery
import importlib.util
import sysconfig


def _load_stdlib_logging():
    stdlib_path = sysconfig.get_path("stdlib")
    spec = importlib.machinery.PathFinder.find_spec("logging", [stdlib_path])
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load standard library logging module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


logging = _load_stdlib_logging()


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
