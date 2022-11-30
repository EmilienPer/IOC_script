class User_interface:
    """
    User Interface master class
    """

    @staticmethod
    def info(title: str, message: str) -> None:
        """
        Show info
        :param title: the title of the pop up
        :param message: the message
        :return:
        """
        raise NotImplemented()

    @staticmethod
    def error(title: str, message: str) -> None:
        """
        Show error
        :param title: the title of the pop up
        :param message: the message
        :return:
        """
        raise NotImplemented()

    @staticmethod
    def askquestion(title, message):
        """
        Ask yes or no for a question
                :param title: the title of the pop up
                :param message: the message
                :return:
        """
        raise NotImplemented()

    def set_os_detected(self, name: str) -> None:
        """
        Set the value of the target name
        :param name: the name of the target
        :return:
        """
        raise NotImplemented()

    def log(self, message, log_type):
        """
                log info
                :param message: the message
                :param log_type: the log_type of log (info, error, warning, debug,...)
                :return:
                """
        raise NotImplemented()

    def set_host_name(self, name: str) -> None:
        """
        Set the OS name
        :param name:
        :return:
        """
        raise NotImplemented()
