"""请求 / 响应数据模型。"""
from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$"
)


def _normalize_time(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None or not str(value).strip():
        return None
    value = str(value).strip()
    if not _TIME_RE.match(value):
        raise ValueError(f"{field_name} 格式应为 YYYY-MM-DD HH:MM:SS")
    value = value.replace("T", " ")
    if len(value) == 16:  # YYYY-MM-DD HH:MM
        value += ":00"
    return value


class SampleCreate(BaseModel):
    code: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=512)

    @field_validator("code", "name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("不能为空")
        return v


class EventCreate(BaseModel):
    custodian: str = Field(..., min_length=1, max_length=64)
    start_time: str
    end_time: Optional[str] = None
    note: str = Field("", max_length=512)

    @field_validator("custodian")
    @classmethod
    def _strip_custodian(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("经手人不能为空")
        return v

    @field_validator("start_time")
    @classmethod
    def _norm_start(cls, v: str) -> str:
        normalized = _normalize_time(v, "起始时间")
        if normalized is None:
            raise ValueError("起始时间不能为空")
        return normalized

    @field_validator("end_time")
    @classmethod
    def _norm_end(cls, v: Optional[str]) -> Optional[str]:
        return _normalize_time(v, "结束时间")

    @model_validator(mode="after")
    def _check_order(self) -> "EventCreate":
        if self.end_time and self.end_time < self.start_time:
            raise ValueError("结束时间不能早于起始时间（逆序问题将在审计中标注，请先修正数据）")
        return self


class BulkImportConfirm(BaseModel):
    """确认批量导入：必须携带预览阶段返回的、绑定当前事件链的摘要令牌。"""

    token: str = Field(..., min_length=1)

    @field_validator("token")
    @classmethod
    def _strip_token(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("预览令牌不能为空，请先上传 CSV 并完成预览")
        return v


class SignoffCreate(BaseModel):
    """结论签署：在当前审计结果上生成不可变快照。"""

    signer: str = Field(..., min_length=1, max_length=64)
    signed_at: str
    remark: str = Field("", max_length=512)

    @field_validator("signer")
    @classmethod
    def _strip_signer(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("签署人不能为空")
        return v

    @field_validator("signed_at")
    @classmethod
    def _norm_signed_at(cls, v: str) -> str:
        normalized = _normalize_time(v, "签署时间")
        if normalized is None:
            raise ValueError("签署时间不能为空")
        return normalized


class SignoffRevoke(BaseModel):
    """撤销签署：必须填写原因，原快照保留。"""

    reason: str = Field(..., min_length=1, max_length=512)

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("撤销原因不能为空")
        return v


class HandoverConfirm(BaseModel):
    """双向交接确认：交出方或接收方填写姓名与确认时间。"""

    side: str = Field(..., pattern="^(from|to)$")
    confirmer_name: str = Field(..., min_length=1, max_length=64)
    confirmed_at: str

    @field_validator("confirmer_name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("确认人姓名不能为空")
        return v

    @field_validator("confirmed_at")
    @classmethod
    def _norm_confirmed_at(cls, v: str) -> str:
        normalized = _normalize_time(v, "确认时间")
        if normalized is None:
            raise ValueError("确认时间不能为空")
        return normalized


class FindingDispose(BaseModel):
    """异常处置：标记已处理 / 重新打开。

    必须携带客户端看到的指纹版本号 ``expected_version``（乐观锁）；
    版本过期时服务端返回 409，客户端应刷新队列后重试。

    标记已处理（resolve）只有该发现**当前未到期租约的认领人**可以执行，
    ``handler`` 必须与认领人一致。
    """

    action: str = Field(..., pattern="^(resolve|reopen)$")
    expected_version: int = Field(..., ge=1)
    handler: str = Field(..., min_length=1, max_length=64)
    note: str = Field("", max_length=512)

    @field_validator("handler")
    @classmethod
    def _strip_handler(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("处置人不能为空")
        return v

    @field_validator("note")
    @classmethod
    def _strip_note(cls, v: str) -> str:
        return v.strip()


class FindingClaim(BaseModel):
    """限时认领 / 过期接管：未处理发现认领 15 分钟。

    认领与接管在服务端单一事务内先重算发现指纹，再同时校验
    ``expected_version`` 与租约状态；租约未到期且属于他人时返回 409，
    到期后允许接管并递增版本。
    """

    expected_version: int = Field(..., ge=1)
    handler: str = Field(..., min_length=1, max_length=64)

    @field_validator("handler")
    @classmethod
    def _strip_handler(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("认领人不能为空")
        return v


class FindingRelease(BaseModel):
    """主动释放认领：只有当前（未到期租约的）认领人可以释放。"""

    expected_version: int = Field(..., ge=1)
    handler: str = Field(..., min_length=1, max_length=64)
    note: str = Field("", max_length=512)

    @field_validator("handler")
    @classmethod
    def _strip_handler(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("认领人不能为空")
        return v

    @field_validator("note")
    @classmethod
    def _strip_note(cls, v: str) -> str:
        return v.strip()
