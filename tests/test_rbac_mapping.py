from actions import ACTION_HANDLERS
import auth


def test_all_action_handlers_have_rbac_mapping() -> None:
    missing: list[str] = []
    for k in ACTION_HANDLERS.keys():
        ku = str(k or "").upper().strip()
        if not ku:
            continue
        if ku in auth.PUBLIC_ACTIONS:
            continue
        if ku not in auth.STATIC_RBAC_PERMISSIONS:
            missing.append(ku)

    assert missing == []

