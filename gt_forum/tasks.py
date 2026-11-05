import json
import uuid

from alibabacloud_green20220302 import models
from alibabacloud_green20220302.client import Client
from alibabacloud_tea_openapi.models import Config
from alibabacloud_tea_util import models as util_models
from celery import shared_task
from django.conf import settings
from django.utils import timezone

import gt_coin.amount as coin_amount
from gt_auth.models import SourceChoice
from gt_admin._models import ReviewStatusChoice
from gt_admin.models import Report, ReportContentTypeChoice
from gt_coin.models import CoinRecordType
from gt_forum.models import PostComment, PostShareWithChoice, PostVersion


ali_client = Client(
    Config(
        access_key_id=settings.ALI_ACCESS_KEY,
        access_key_secret=settings.ALI_ACCESS_SECRET,
        connect_timeout=3000,
        read_timeout=6000,
        region_id="cn-shanghai",
        endpoint="green-cip.cn-shanghai.aliyuncs.com",
    )
)


def review_with_aliyun(
    content: str, service_code="comment_detection", report_info: dict | None = None
):
    if (settings.DEBUG and getattr(settings, "LOCAL_PREVIEW_MODE", False) and
            settings.WEBAUTHN_RP_ID == "localhost"):
        return {"reviewer_type": "local_preview", "reviewer": "local_preview",
                "review_time": timezone.now().isoformat(), "status": ReviewStatusChoice.ACCEPTED,
                "message": "本机预览测试审核；未调用外部服务"}
    i = 0
    strs = []
    while i + 2 < len(content):
        strs.append(content[i : i + 590])
        i += 580

    status = ReviewStatusChoice.PENDING
    message = {
        "reviewer_type": "machine",
        "reviewer": "aliyun",
        "review_time": timezone.now().isoformat(),
    }
    _message = []
    flag = False
    for text in strs:
        service_parameters = {"content": text, "dataId": str(uuid.uuid1())}
        text_moderation_request = models.TextModerationRequest(
            service=service_code,
            service_parameters=json.dumps(service_parameters),
        )
        runtime = util_models.RuntimeOptions()
        runtime.read_timeout = 10000
        runtime.connect_timeout = 10000
        response = ali_client.text_moderation_with_options(
            text_moderation_request, runtime
        )
        resultData = response.body.data
        labels = resultData.labels
        reason = resultData.reason
        print(labels, reason)
        if labels != "":
            if reason:
                reason = json.loads(reason)
            else:
                reason = {"riskLevel": "low"}
            _message.append(
                f"【{reason.get('riskTips', '无违规提示')}】{reason.get('riskWords', '无敏感词列表')}"
            )
            if reason["riskLevel"] == "low":
                ...
            elif reason["riskLevel"] == "medium":
                flag = True
            else:
                status = ReviewStatusChoice.REJECTED
                break
    else:
        _message.append("OK")

    if status == ReviewStatusChoice.PENDING:
        status = ReviewStatusChoice.ACCEPTED
    message["message"] = "\n".join(_message)
    message["status"] = status
    if flag:
        if service_code == "nickname_detection":
            message["status"] = ReviewStatusChoice.REJECTED
        if report_info:
            Report.objects.create(
                **report_info,
                explanation=message["message"],
                extra_content=Report.get_extra_content(**report_info),
            )

    return message


@shared_task
def review_post_version(id, retry=True):
    post_version = PostVersion.objects.get(id=id)
    post = post_version.post
    if post_version.review_status == ReviewStatusChoice.PENDING:
        content = f"标题:\n{post_version.title}\n内容:\n{post_version.content}"
        try:
            message = review_with_aliyun(
                content,
                report_info={
                    "content_id": post.id,
                    "content_type": ReportContentTypeChoice.POST,
                },
            )
            if message == None:
                raise Exception("审核失败")
        except Exception as e:
            if retry:
                review_post_version.delay(id, retry=False)
                return
            else:
                raise e

        post_version.refresh_from_db(fields=["review_status"])
        if post_version.review_status != ReviewStatusChoice.PENDING:
            return
        post_version.review_status = message["status"]
        post_version.save(update_fields=["review_status"])
        post.review_message.append(message)
        post.save(update_fields=["review_message"])
        if message["status"] >= ReviewStatusChoice.NO_NEED:
            post_version.write_to_post()
            post_version.user.add_captcha_expire_seconds(300)
        elif post.review_status == ReviewStatusChoice.PENDING:
            post.review_status = message["status"]
            post.save(update_fields=["review_status"])
    # 判断每日发帖奖励
    coin = post_version.user.coin
    if post_version.review_status >= ReviewStatusChoice.NO_NEED:
        if (
            not coin.record_today.post_reward
            and post_version.version == 1
            and post_version.share_with > PostShareWithChoice.PRIVATE
        ):
            coin.add_record(
                coin_amount.get_post_reward_amount(post_version.post.type),
                CoinRecordType.DAILY,
                detail=f"每日发帖奖励",
            )
            coin.record_today.post_reward = True
            coin.record_today.save(update_fields=["post_reward"])
    elif post_version.review_status == ReviewStatusChoice.REJECTED:
        coin.add_record(
            coin_amount.POST_VIOLATION,
            CoinRecordType.PUNISH,
            "帖子违规",
            allow_negative=True,
        )


@shared_task
def review_post_comment(id, retry=True):
    post_comment = PostComment.objects.get(id=id)
    if post_comment.review_status == ReviewStatusChoice.PENDING:
        try:
            message = review_with_aliyun(
                post_comment.content,
                report_info={
                    "content_id": post_comment.id,
                    "content_type": ReportContentTypeChoice.COMMENT,
                },
            )
        except Exception as e:
            if retry:
                review_post_comment.delay(id, retry=False)
                return
            else:
                raise e
        post_comment.refresh_from_db(fields=["review_status"])
        if post_comment.review_status != ReviewStatusChoice.PENDING:
            return
        post_comment.review_status = message["status"]
        post_comment.review_message.append(message)
        post_comment.save(update_fields=["review_status", "review_message"])

    coin = post_comment.user.coin
    if post_comment.review_status >= ReviewStatusChoice.NO_NEED:

        # 如果回复了发帖人评论的内容就只有一个通知
        if post_comment.reply_to and post_comment.reply_to.author == post_comment.post.author:
            post_comment.create_reply_notification()
        else:
            post_comment.create_post_comment_notification()
            post_comment.create_reply_notification()

        # 判断每日评论奖励
        if not coin.record_today.comment_reward:
            coin.add_record(
                coin_amount.COMMENT_REWARD,
                CoinRecordType.DAILY,
                detail=f"每日评论奖励",
            )
            coin.record_today.comment_reward = True
            coin.record_today.save(update_fields=["comment_reward"])
        post_comment.user.add_captcha_expire_seconds()
    elif post_comment.review_status == ReviewStatusChoice.REJECTED:
        coin.add_record(
            coin_amount.COMMENT_VIOLATION,
            CoinRecordType.PUNISH,
            "评论违规",
            allow_negative=True,
        )
