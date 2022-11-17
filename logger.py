class Logger(object):
    level = 0
    action = print

    @staticmethod
    def log(msg: str | list, level: int = 0):
        if isinstance(msg, list):
            msg = ' '.join(msg)
        if level >= Logger.level:
            Logger.action(msg)
