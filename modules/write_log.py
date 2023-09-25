import logging
import settings


def log_writer(message):
    logging.basicConfig(
        filename=settings.log_file_path,
        encoding='utf-8',
        level=logging.INFO,
        format='[%(asctime)s] : %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )
    logging.info(message)
