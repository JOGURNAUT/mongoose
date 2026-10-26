from sqlmodel import SQLModel, Session, create_engine, select

from app.config import DATABASE_PATH
from app.models import Alert

engine = create_engine(f"sqlite:///{DATABASE_PATH}", connect_args={"check_same_thread": False})


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def save_alert(alert: Alert) -> Alert:
    with Session(engine) as session:
        session.add(alert)
        session.commit()
        session.refresh(alert)
        return alert


def get_alert(alert_id: int) -> Alert | None:
    with Session(engine) as session:
        return session.get(Alert, alert_id)


def list_alerts(limit: int = 50) -> list[Alert]:
    with Session(engine) as session:
        statement = select(Alert).order_by(Alert.id.desc()).limit(limit)
        return list(session.exec(statement))
