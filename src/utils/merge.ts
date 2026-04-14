import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * 클래스 네임을 조건부로 합치고, 테일윈드 클래스 충돌을 해결해주는 유틸리티입니다.
 * (머지 스크립트)
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
