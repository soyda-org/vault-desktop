from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QSplitter,
    QStackedWidget,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


def _panel(*, title: str, description: str | None = None) -> tuple[QWidget, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("surfacePanel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 14, 14, 14)
    layout.setSpacing(8)

    if title:
        title_label = QLabel(title)
        title_label.setObjectName("surfacePanelTitle")
        layout.addWidget(title_label)

    if description:
        description_label = QLabel(description)
        description_label.setObjectName("surfacePanelBody")
        description_label.setWordWrap(True)
        layout.addWidget(description_label)

    return frame, layout


def _panel_shell() -> tuple[QWidget, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("surfacePanel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 14, 14, 14)
    layout.setSpacing(8)
    return frame, layout


def _divider() -> QFrame:
    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.HLine)
    frame.setFrameShadow(QFrame.Shadow.Plain)
    frame.setObjectName("surfaceDivider")
    frame.setFixedHeight(2)
    return frame


class _CenteredDivider(QWidget):
    def __init__(self, ratio: float = 0.5) -> None:
        super().__init__()
        self._ratio = ratio
        self._line = _divider()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(0)
        layout.addStretch(1)
        layout.addWidget(self._line, 0)
        layout.addStretch(1)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        self._line.setFixedWidth(max(160, int(self.width() * self._ratio)))
        super().resizeEvent(event)


class SystemWorkspaceView(QWidget):
    def __init__(
        self,
        *,
        header_label: QLabel,
        status_label: QLabel,
        session_label: QLabel,
        connection_label: QLabel,
        session_state_label: QLabel,
        vault_state_label: QLabel,
        api_details_label: QLabel,
        form_widgets: dict[str, QWidget],
        auth_buttons: dict[str, QWidget],
        preference_widgets: dict[str, QWidget],
        utility_buttons: dict[str, QWidget],
        log_widgets: dict[str, QWidget],
    ) -> None:
        super().__init__()
        self.panel_stack = QStackedWidget()

        connect_panel, connect_layout = _panel_shell()
        connection_label.setObjectName("connectionStateText")
        session_state_label.setObjectName("connectionStateText")
        vault_state_label.setObjectName("connectionStateText")

        content_column = QVBoxLayout()
        content_column.setContentsMargins(0, 0, 0, 0)
        content_column.setSpacing(6)

        connection_row = QHBoxLayout()
        connection_row.setContentsMargins(0, 0, 0, 0)
        connection_row.setSpacing(12)
        auth_buttons["probe"].setProperty("statusRowButton", True)
        connection_row.addWidget(auth_buttons["probe"], 0)
        connection_row.addWidget(connection_label, 0)
        connection_row.addWidget(session_state_label, 0)
        connection_row.addWidget(vault_state_label, 0)
        connection_row.addStretch(1)
        connect_layout.addLayout(connection_row)

        for key in ("identifier", "password", "device_name", "platform"):
            form_widgets[key].setMinimumWidth(260)
            form_widgets[key].setMaximumWidth(560)
            content_column.addWidget(form_widgets[key], 0)

        primary_row = QHBoxLayout()
        primary_row.setContentsMargins(0, 2, 0, 0)
        primary_row.setSpacing(4)
        primary_row.addStretch(1)
        primary_row.addWidget(auth_buttons["signup"])
        primary_row.addWidget(auth_buttons["login"])
        primary_row.addWidget(utility_buttons["logout"])
        primary_row.addWidget(utility_buttons["close"])
        primary_row.addStretch(1)
        content_column.addLayout(primary_row)
        content_column.addWidget(preference_widgets["persist_logs"], 0, Qt.AlignmentFlag.AlignCenter)
        content_column.addWidget(status_label, 0)

        content_container = QWidget()
        content_container.setObjectName("contentContainer")
        content_container.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)
        content_container.setLayout(content_column)

        content_wrapper = QHBoxLayout()
        content_wrapper.setContentsMargins(0, 0, 0, 0)
        content_wrapper.setSpacing(0)
        content_wrapper.addStretch(1)
        content_wrapper.addWidget(content_container, 0)
        content_wrapper.addStretch(1)
        connect_layout.addStretch(1)
        connect_layout.addLayout(content_wrapper)
        connect_layout.addStretch(1)

        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(0)
        meta_row.addStretch(1)
        meta_row.addWidget(api_details_label, 1)
        meta_row.addStretch(1)
        connect_layout.addLayout(meta_row)

        messages_panel, messages_layout = _panel_shell()

        log_toolbar = QHBoxLayout()
        log_toolbar.setContentsMargins(0, 0, 0, 0)
        log_toolbar.setSpacing(6)
        log_toolbar.addWidget(log_widgets["copy"])
        log_toolbar.addWidget(log_widgets["clear"])
        log_toolbar.addStretch(1)
        messages_layout.addLayout(log_toolbar)
        messages_layout.addWidget(log_widgets["list"], 1)

        self.panel_stack.addWidget(connect_panel)
        self.panel_stack.addWidget(messages_panel)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.panel_stack, 1)

    def set_current_panel(self, name: str) -> None:
        self.panel_stack.setCurrentIndex(0 if name == "service" else 1)


class VaultWorkspaceView(QWidget):
    def __init__(
        self,
        *,
        pin_widgets: dict[str, QWidget],
        recovery_widgets: dict[str, QWidget],
        help_button: QWidget,
        load_buttons: dict[str, QWidget],
        session_actions: dict[str, QWidget],
        preference_widgets: dict[str, QWidget],
        tabs: QWidget,
    ) -> None:
        super().__init__()
        self.panel_stack = QStackedWidget()

        access_panel, access_layout = _panel(
            title="",
            description=None,
        )
        content_column = QVBoxLayout()
        content_column.setContentsMargins(0, 0, 0, 0)
        content_column.setSpacing(6)

        pin_row = QHBoxLayout()
        pin_row.setContentsMargins(0, 6, 0, 0)
        pin_row.setSpacing(8)
        pin_row.addWidget(pin_widgets["input"], 1)

        pin_focus_area = QVBoxLayout()
        pin_focus_area.setContentsMargins(0, 0, 0, 0)
        pin_focus_area.setSpacing(0)
        pin_focus_area.addStretch(1)
        pin_focus_area.addLayout(pin_row)
        pin_focus_area.addStretch(1)
        content_column.addLayout(pin_focus_area, 3)
        content_column.addStretch(1)

        help_row = QHBoxLayout()
        help_row.setContentsMargins(0, 0, 0, 0)
        help_row.setSpacing(8)
        help_row.addStretch(1)
        help_row.addWidget(help_button)
        help_row.addStretch(1)
        content_column.addLayout(help_row)

        manage_row = QHBoxLayout()
        manage_row.setContentsMargins(0, 0, 0, 0)
        manage_row.setSpacing(8)
        manage_row.addStretch(1)
        manage_row.addWidget(session_actions["logout"])
        manage_row.addStretch(1)
        content_column.addLayout(manage_row)
        content_column.addSpacing(2)

        settings_row = QHBoxLayout()
        settings_row.setContentsMargins(0, 0, 0, 0)
        settings_row.setSpacing(0)
        settings_row.addStretch(1)
        settings_row.addWidget(recovery_widgets["toggle"])
        settings_row.addStretch(1)
        content_column.addLayout(settings_row)
        content_column.addWidget(recovery_widgets["container"])

        content_container = QWidget()
        content_container.setObjectName("contentContainer")
        content_container.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)
        content_container.setLayout(content_column)

        content_wrapper = QHBoxLayout()
        content_wrapper.setContentsMargins(0, 0, 0, 0)
        content_wrapper.setSpacing(0)
        content_wrapper.addStretch(1)
        content_wrapper.addWidget(content_container, 0)
        content_wrapper.addStretch(1)
        access_layout.addLayout(content_wrapper, 1)

        workspace_panel, workspace_layout = _panel_shell()
        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        workspace_layout.addWidget(tabs, 1)
        workspace_footer_row = QHBoxLayout()
        workspace_footer_row.setContentsMargins(0, 0, 0, 0)
        workspace_footer_row.setSpacing(8)
        workspace_footer_row.addWidget(preference_widgets["keep_open"], 0)
        workspace_footer_row.addStretch(1)
        workspace_footer_row.addWidget(session_actions["lock"], 0)
        workspace_layout.addLayout(workspace_footer_row)

        self.panel_stack.addWidget(access_panel)
        self.panel_stack.addWidget(workspace_panel)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.panel_stack, 1)

    def set_current_panel(self, name: str) -> None:
        self.panel_stack.setCurrentIndex(0 if name == "access" else 1)


class GeneratorWorkspaceView(QWidget):
    def __init__(self, *, generator_widgets: dict[str, QWidget]) -> None:
        super().__init__()

        generator_panel, generator_layout = _panel(
            title="Password generator",
            description=None,
        )
        generator_panel.setProperty("panelVariant", "secondary")

        policy_row = QHBoxLayout()
        policy_row.setContentsMargins(0, 0, 0, 0)
        policy_row.setSpacing(6)
        policy_row.addWidget(QLabel("Length"))
        policy_row.addWidget(generator_widgets["length"])
        policy_row.addWidget(generator_widgets["upper"])
        policy_row.addWidget(generator_widgets["lower"])
        policy_row.addWidget(generator_widgets["digits"])
        policy_row.addWidget(generator_widgets["symbols"])
        policy_row.addStretch(1)
        generator_layout.addLayout(policy_row)

        output_row = QHBoxLayout()
        output_row.setContentsMargins(0, 0, 0, 0)
        output_row.setSpacing(8)
        output_row.addWidget(generator_widgets["output"], 1)
        output_row.addWidget(generator_widgets["generate"])
        output_row.addWidget(generator_widgets["copy"])
        generator_layout.addLayout(output_row)

        generator_layout.addWidget(_CenteredDivider(0.5))

        quick_title = QLabel("Quick encrypt / decrypt")
        quick_title.setObjectName("sectionTitle")
        generator_layout.addWidget(quick_title)

        method_row = QHBoxLayout()
        method_row.setContentsMargins(0, 0, 0, 0)
        method_row.setSpacing(8)
        method_row.addWidget(generator_widgets["method"], 0)
        method_row.addWidget(generator_widgets["method_help"], 0)
        method_row.addWidget(generator_widgets["passphrase"], 1)
        method_row.addWidget(generator_widgets["encrypt"], 0)
        method_row.addWidget(generator_widgets["decrypt"], 0)
        method_row.addWidget(generator_widgets["copy_output"], 0)
        generator_layout.addLayout(method_row)

        quick_splitter = QSplitter(Qt.Orientation.Vertical)
        quick_splitter.setChildrenCollapsible(False)
        quick_splitter.setHandleWidth(4)
        quick_splitter.addWidget(generator_widgets["quick_input"])
        quick_splitter.addWidget(generator_widgets["quick_output"])
        quick_splitter.setStretchFactor(0, 1)
        quick_splitter.setStretchFactor(1, 1)
        quick_splitter.setSizes([1, 1])
        generator_layout.addWidget(quick_splitter, 1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(generator_panel, 1)
