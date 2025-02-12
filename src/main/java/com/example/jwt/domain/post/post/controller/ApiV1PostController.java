package com.example.jwt.domain.post.post.controller;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.post.post.dto.PageDto;
import com.example.jwt.domain.post.post.dto.PostWithContentDto;
import com.example.jwt.domain.post.post.entity.Post;
import com.example.jwt.domain.post.post.service.PostService;
import com.example.jwt.global.Rq;
import com.example.jwt.global.dto.RsData;
import com.example.jwt.global.exception.ServiceException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/posts")
@RequiredArgsConstructor
public class ApiV1PostController {

    private final PostService postService;
    private final Rq rq;

    record StatisticsResBody(long postCount, long postPublishedCount, long postListedCount) {
    }

    @GetMapping("/statistics")
    public RsData<StatisticsResBody> getStatistics() {

        Member actor = rq.getActor();

        if(!actor.isAdmin()) {
            return new RsData<>("403-1","접근 권한이 없습니다.");
        }

        return new RsData<>(
                "200-1",
                "통계 조회가 완료되었습니다.",
                new StatisticsResBody(
                        10,
                        10,
                        10
                )
        );
    }

    @GetMapping
    @Transactional(readOnly = true)
    public RsData<PageDto> getItems(@RequestParam(defaultValue = "1") int page,
                                    @RequestParam(defaultValue = "3") int pageSize,
                                    @RequestParam(defaultValue = "title") String keywordType,
                                    @RequestParam(defaultValue = "") String keyword) {
        Page<Post> postPage = postService.getListedItems(page, pageSize, keywordType, keyword);

        return new RsData<>(
                "200-1",
                "글 목록 조회가 완료되었습니다.",
                new PageDto(postPage)
        );

    }


    @GetMapping("/mine")
    @Transactional(readOnly = true)
    public RsData<PageDto> getMines(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "3") int pageSize,
            @RequestParam(defaultValue = "title") String keywordType,
            @RequestParam(defaultValue = "") String keyword
    ) {

        Member actor = rq.getActor();
        Page<Post> pagePost = postService.getMines(actor, page, pageSize, keywordType, keyword);

        return new RsData<>("200-1",
                "내 글 목록 조회가 완료되었습니다.",
                new PageDto(pagePost)
        );

    }

    @GetMapping("{id}")
    @Transactional(readOnly = true)
    public RsData<PostWithContentDto> getItem(@PathVariable long id) {

        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        if (!post.isPublished()) {
            Member actor = rq.getActor();
            post.canRead(actor);
        }

        return new RsData<>(
                "200-1",
                "%d번 글을 조회하였습니다.".formatted(id),
                new PostWithContentDto(post)
        );
    }

    record WriteReqBody(@NotBlank String title,
                        @NotBlank String content,
                        boolean published,
                        boolean listed) {
    }

    @PostMapping
    @Transactional
    public RsData<PostWithContentDto> write(@RequestBody @Valid WriteReqBody reqBody) {

        Member actor = rq.getActor();
        Member realActor = rq.getRealActor(actor);


        Post post = postService.write(realActor, reqBody.title(), reqBody.content(), reqBody.published(), reqBody.listed());

        return new RsData<>(
                "201-1",
                "%d번 글 작성이 완료되었습니다.".formatted(post.getId()),
                new PostWithContentDto(post)
        );
    }

    record ModifyReqBody(@NotBlank String title, @NotBlank String content) {
    }

    @PutMapping("{id}")
    @Transactional
    public RsData<PostWithContentDto> modify(@PathVariable long id, @RequestBody @Valid ModifyReqBody reqBody) {

        Member actor = rq.getActor(); // 야매

        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        post.canModify(actor);

        postService.modify(post, reqBody.title(), reqBody.content());

        return new RsData<>(
                "200-1",
                "%d번 글 수정이 완료되었습니다.".formatted(id),
                new PostWithContentDto(post)
        );
    }

    @DeleteMapping("{id}")
    @Transactional
    public RsData<Void> delete(@PathVariable long id) {

        Member actor = rq.getActor();

        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        post.canDelete(actor);
        postService.delete(post);

        return new RsData<>(
                "200-1",
                "%d번 글 삭제가 완료되었습니다.".formatted(id)
        );

    }


}