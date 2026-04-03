from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
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
    frame.setFixedHeight(1)
    return frame


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
        content_column.setSpacing(10)

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
        primary_row.setContentsMargins(0, 4, 0, 0)
        primary_row.setSpacing(6)
        primary_row.addStretch(1)
        primary_row.addWidget(auth_buttons["login"])
        primary_row.addWidget(auth_buttons["signup"])
        primary_row.addStretch(1)
        content_column.addLayout(primary_row)

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
        connect_layout.addStretch(1)
        connect_layout.addLayout(content_wrapper)
        connect_layout.addStretch(1)

        messages_panel, messages_layout = _panel(
            title="System messages",
            description=(
                "Keep recent diagnostics and local system activity in one place."
            ),
        )

        utility_row = QHBoxLayout()
        utility_row.setContentsMargins(0, 2, 0, 0)
        utility_row.setSpacing(6)
        utility_row.addWidget(utility_buttons["logout"])
        utility_row.addWidget(utility_buttons["close"])
        utility_row.addStretch(1)
        messages_layout.addLayout(utility_row)
        messages_layout.addWidget(_divider())
        messages_layout.addWidget(api_details_label)
        messages_layout.addWidget(status_label)

        log_intro = QLabel(
            "Recent network progress and security actions appear here in time order."
        )
        log_intro.setObjectName("surfacePanelBody")
        log_intro.setWordWrap(True)
        messages_layout.addWidget(log_intro)

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
        summary_label: QLabel,
        pin_widgets: dict[str, QWidget],
        recovery_widgets: dict[str, QWidget],
        status_labels: dict[str, QLabel],
        generator_widgets: dict[str, QWidget],
        load_buttons: dict[str, QWidget],
        session_actions: dict[str, QWidget],
        tabs: QWidget,
    ) -> None:
        super().__init__()

        access_panel, access_layout = _panel(
            title="Vault access",
            description=(
                "Use PIN for daily unlock on this desktop, keep recovery as fallback, "
                "and lock the in-memory vault key when you are done."
            ),
        )
        access_layout.addWidget(summary_label)
        access_layout.addWidget(status_labels["unlock_source"])
        access_layout.addWidget(status_labels["next_step"])
        access_layout.addWidget(status_labels["pin_status"])

        pin_row = QHBoxLayout()
        pin_row.setContentsMargins(0, 6, 0, 0)
        pin_row.setSpacing(8)
        pin_row.addWidget(pin_widgets["input"], 1)
        pin_row.addWidget(pin_widgets["unlock"])
        pin_row.addWidget(session_actions["lock"])
        access_layout.addLayout(pin_row)

        manage_row = QHBoxLayout()
        manage_row.setContentsMargins(0, 0, 0, 0)
        manage_row.setSpacing(8)
        manage_row.addWidget(pin_widgets["enroll"])
        manage_row.addWidget(pin_widgets["remove"])
        manage_row.addStretch(1)
        manage_row.addWidget(session_actions["logout"])
        access_layout.addLayout(manage_row)

        access_layout.addWidget(pin_widgets["confirm_input"])
        access_layout.addWidget(status_labels["scope"])
        access_layout.addWidget(status_labels["confirmation"])
        access_layout.addWidget(recovery_widgets["toggle"])
        access_layout.addWidget(recovery_widgets["container"])

        generator_panel, generator_layout = _panel(
            title="Password generator",
            description=(
                "Generate a password at any time, even before the vault is unlocked, "
                "then copy it into a credential payload when needed."
            ),
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

        workspace_panel, workspace_layout = _panel(
            title="Vault workspace",
            description=(
                "Load credentials, notes, or files, then work inside the section tabs "
                "below. Locked sessions can still browse list metadata but sensitive "
                "detail remains hidden."
            ),
        )
        load_row = QHBoxLayout()
        load_row.setContentsMargins(0, 8, 0, 0)
        load_row.setSpacing(8)
        load_row.addWidget(load_buttons["credentials"])
        load_row.addWidget(load_buttons["notes"])
        load_row.addWidget(load_buttons["files"])
        load_row.addStretch(1)
        load_row.addWidget(load_buttons["all"])
        workspace_layout.addLayout(load_row)

        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        workspace_layout.addWidget(tabs, 1)

        sidebar = QVBoxLayout()
        sidebar.setContentsMargins(0, 0, 0, 0)
        sidebar.setSpacing(16)
        sidebar.addWidget(access_panel)
        sidebar.addWidget(generator_panel)
        sidebar.addStretch(1)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(16)
        body.addLayout(sidebar, 2)
        body.addWidget(workspace_panel, 3)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(body, 1)
