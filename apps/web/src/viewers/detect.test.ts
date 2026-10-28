import { describe, expect, it } from 'vitest';
import type { Body } from '~/model/flow';
import { detectBody, parseContentType, sniffText } from './detect';

const body = (text: string | null, contentType: string | null, extra: Partial<Body> = {}): Body => ({
  text,
  contentType,
  size: text?.length ?? 0,
  truncated: false,
  ...extra,
});

describe('parseContentType', () => {
  it('splits mime and parameters', () => {
    expect(parseContentType('application/json; charset=utf-8')).toEqual({ mime: 'application/json', params: { charset: 'utf-8' } });
    expect(parseContentType('multipart/form-data; boundary="----x"')).toEqual({ mime: 'multipart/form-data', params: { boundary: '----x' } });
    expect(parseContentType(null)).toEqual({ mime: null, params: {} });
  });
});

describe('detectBody', () => {
  it('trusts a JSON content-type', () => {
    expect(detectBody(body('{"a":1}', 'application/json; charset=utf-8')).kind).toBe('json');
    expect(detectBody(body('[]', 'application/vnd.api+json')).kind).toBe('json');
  });
  it('sniffs JSON without a content-type', () => {
    expect(detectBody(body('  {"a":1}', null)).kind).toBe('json');
    expect(detectBody(body('[1,2]', 'text/plain')).kind).toBe('text');
  });
  it('maps the text families', () => {
    expect(detectBody(body('a=1&b=2', 'application/x-www-form-urlencoded')).kind).toBe('form');
    expect(detectBody(body('<!doctype html><html></html>', 'text/html; charset=utf-8')).kind).toBe('html');
    expect(detectBody(body('<?xml version="1.0"?><a/>', 'application/xml')).kind).toBe('xml');
    expect(detectBody(body('body{}', 'text/css')).kind).toBe('css');
    expect(detectBody(body('1+1', 'application/javascript')).kind).toBe('js');
    expect(detectBody(body('<svg xmlns="http://www.w3.org/2000/svg"/>', 'image/svg+xml')).kind).toBe('xml');
  });
  it('finds a multipart boundary from the header or the bytes', () => {
    const text = '--abc\r\nContent-Disposition: form-data; name="x"\r\n\r\n1\r\n--abc--\r\n';
    expect(detectBody(body(text, 'multipart/form-data; boundary=abc'))).toMatchObject({ kind: 'multipart', boundary: 'abc' });
    expect(detectBody(body(text, null))).toMatchObject({ kind: 'multipart', boundary: 'abc' });
  });
  it('treats binary payloads by mime, then by bytes', () => {
    expect(detectBody(body(null, 'image/png', { base64: 'iVBORw0KGgo=', size: 8 })).kind).toBe('image');
    expect(detectBody(body(null, 'application/octet-stream', { base64: 'AAEC', size: 3 })).kind).toBe('binary');
    // NUL bytes without a mime → binary
    expect(detectBody(body(null, null, { base64: 'AAAAAA==', size: 4 })).kind).toBe('binary');
  });
  it('is empty for nothing', () => {
    expect(detectBody(null).kind).toBe('empty');
    expect(detectBody(body('', 'application/json')).kind).toBe('empty');
  });
  it('sniffText falls back to text', () => {
    expect(sniffText('hello world')).toBe('text');
    expect(sniffText('q=lamp&page=2')).toBe('form');
  });
});
