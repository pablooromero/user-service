package com.user_service.user_service.dtos;

public record OrderItemRecord(Long id, Long orderId, Long productId, Integer quantity) {
}