from PyQt5 import QtCore, QtGui, QtWidgets

import ui.Ui_wait_dialog

class LoadingProgress(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.ui = ui.Ui_wait_dialog.Ui_Form()
        self.ui.setupUi(self)

        self.setWindowFlags(QtCore.Qt.WindowTitleHint)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.movie = QtGui.QMovie('image/loading.gif')
        self.ui.label_gif.setMovie(self.movie)
        self.ui.label_gif.setScaledContents(True)
        self.ui.label_prompt.setAlignment(QtCore.Qt.AlignCenter)

    def pop_start(self, msg):
        self.movie.start()
        self.ui.label_prompt.setText(msg)
        self.show()

    def pop_stop(self):
        self.movie.stop()
        self.close()


