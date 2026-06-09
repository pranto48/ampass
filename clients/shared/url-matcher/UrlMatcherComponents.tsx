import React, { useState, useEffect, useRef } from 'react';
import { SegregatedMatches } from './UrlMatcher';

interface QuickFillIconProps {
  inputRef: React.RefObject<HTMLInputElement>;
  matches: SegregatedMatches;
  onSelect: (credentials: any) => void;
}

/**
 * Quick Fill Floating Icon Component
 * Hovers near the password/username input field. Clicking it shows exactMatch
 * and sharedBackendMatches options for instant fill.
 */
export const QuickFillIcon: React.FC<QuickFillIconProps> = ({ inputRef, matches, onSelect }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Quick fill merges strict exact matches and Apple-linked backend matches
  const quickMatches = [...matches.exactMatch, ...matches.sharedBackendMatches];

  useEffect(() => {
    const updatePosition = () => {
      if (inputRef.current) {
        const rect = inputRef.current.getBoundingClientRect();
        setPosition({
          top: rect.top + window.scrollY + (rect.height - 20) / 2,
          left: rect.left + rect.width - 24 + window.scrollX,
        });
      }
    };

    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition);

    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition);
    };
  }, [inputRef]);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  if (quickMatches.length === 0) return null;

  return (
    <div ref={containerRef} style={{ position: 'absolute', top: position.top, left: position.left, zIndex: 99999 }}>
      {/* Tiny Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
          border: 'none',
          borderRadius: '50%',
          width: '20px',
          height: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          cursor: 'pointer',
          boxShadow: '0 2px 6px rgba(99, 102, 241, 0.4)',
          color: '#ffffff',
          fontSize: '10px',
          padding: 0,
          transition: 'transform 0.15s ease-in-out',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.15)')}
        onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1.0)')}
        title="AMPass Auto Fill"
      >
        ⚡
      </button>

      {/* Floating Menu */}
      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: '24px',
            right: 0,
            width: '260px',
            backgroundColor: '#09090b',
            border: '1px solid #27272a',
            borderRadius: '8px',
            boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5), 0 8px 10px -6px rgba(0,0,0,0.5)',
            padding: '6px 0',
            fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
            color: '#fafafa',
          }}
        >
          <div
            style={{
              padding: '6px 12px',
              fontSize: '11px',
              color: '#71717a',
              borderBottom: '1px solid #18181b',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            Quick Fill Accounts
          </div>
          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {quickMatches.map((item, idx) => (
              <button
                key={item.id || idx}
                onClick={() => {
                  onSelect(item);
                  setIsOpen(false);
                }}
                style={{
                  width: '100%',
                  background: 'none',
                  border: 'none',
                  color: '#f4f4f5',
                  textAlign: 'left',
                  padding: '8px 12px',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  transition: 'background-color 0.15s ease',
                  outline: 'none',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#18181b')}
                onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              >
                <span style={{ fontWeight: 500, fontSize: '12px' }}>{item.title || 'Untitled'}</span>
                <span style={{ color: '#a1a1aa', fontSize: '11px', marginTop: '2px' }}>{item.username}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

interface AdvancedVaultViewProps {
  matches: SegregatedMatches;
  onSelect: (credentials: any) => void;
}

/**
 * Advanced Vault Context-Segregation Component
 * Renders tabbed lists of Subdomain variations and Port variations.
 */
export const AdvancedVaultView: React.FC<AdvancedVaultViewProps> = ({ matches, onSelect }) => {
  const [activeTab, setActiveTab] = useState<'subdomains' | 'ports'>('subdomains');

  const subdomains = matches.subdomainMatches;
  const ports = matches.portVariations;

  return (
    <div
      style={{
        backgroundColor: '#09090b',
        border: '1px solid #27272a',
        borderRadius: '12px',
        padding: '24px',
        color: '#f4f4f5',
        fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
        maxWidth: '560px',
        margin: '20px auto',
        boxShadow: '0 20px 25px -5px rgba(0,0,0,0.4), 0 10px 10px -5px rgba(0,0,0,0.4)',
      }}
    >
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600, margin: '0 0 6px 0', color: '#ffffff', letterSpacing: '-0.02em' }}>
          Advanced Vault Context
        </h2>
        <p style={{ fontSize: '0.825rem', color: '#71717a', margin: 0 }}>
          Credentials detected on this domain with subdomain or port variations.
        </p>
      </div>

      {/* Modern Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #18181b', marginBottom: '20px', gap: '12px' }}>
        <button
          onClick={() => setActiveTab('subdomains')}
          style={{
            padding: '8px 4px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'subdomains' ? '2px solid #6366f1' : '2px solid transparent',
            color: activeTab === 'subdomains' ? '#fafafa' : '#71717a',
            cursor: 'pointer',
            fontWeight: 500,
            fontSize: '0.85rem',
            transition: 'all 0.15s ease',
          }}
        >
          Subdomains ({subdomains.length})
        </button>
        <button
          onClick={() => setActiveTab('ports')}
          style={{
            padding: '8px 4px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'ports' ? '2px solid #f59e0b' : '2px solid transparent',
            color: activeTab === 'ports' ? '#fafafa' : '#71717a',
            cursor: 'pointer',
            fontWeight: 500,
            fontSize: '0.85rem',
            transition: 'all 0.15s ease',
          }}
        >
          Port Variations ({ports.length})
        </button>
      </div>

      {/* Tab Panels */}
      <div>
        {activeTab === 'subdomains' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {subdomains.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px 10px', color: '#3f3f46', fontSize: '0.85rem' }}>
                No subdomain variations matching base domain.
              </div>
            ) : (
              subdomains.map((item, idx) => (
                <div
                  key={item.id || idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    backgroundColor: '#18181b',
                    borderRadius: '8px',
                    padding: '14px 18px',
                    border: '1px solid #27272a',
                    transition: 'border-color 0.2s, box-shadow 0.2s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#3f3f46';
                    e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = '#27272a';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <div style={{ flex: 1, paddingRight: '12px' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.925rem', color: '#ffffff' }}>{item.title || 'Untitled'}</div>
                    <div style={{ fontSize: '0.8rem', color: '#a1a1aa', marginTop: '3px' }}>{item.username}</div>
                    <div style={{ fontSize: '0.725rem', color: '#6366f1', marginTop: '6px', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                      {item.url}
                    </div>
                  </div>
                  <button
                    onClick={() => onSelect(item)}
                    style={{
                      backgroundColor: '#6366f1',
                      border: 'none',
                      color: '#ffffff',
                      borderRadius: '6px',
                      padding: '8px 14px',
                      fontSize: '0.775rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                      flexShrink: 0,
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#4f46e5')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '#6366f1')}
                  >
                    Select
                  </button>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'ports' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {ports.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px 10px', color: '#3f3f46', fontSize: '0.85rem' }}>
                No port variations matching base domain.
              </div>
            ) : (
              ports.map((item, idx) => (
                <div
                  key={item.id || idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    backgroundColor: '#18181b',
                    borderRadius: '8px',
                    padding: '14px 18px',
                    border: '1px solid #27272a',
                    transition: 'border-color 0.2s, box-shadow 0.2s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#3f3f46';
                    e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = '#27272a';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <div style={{ flex: 1, paddingRight: '12px' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.925rem', color: '#ffffff' }}>{item.title || 'Untitled'}</div>
                    <div style={{ fontSize: '0.8rem', color: '#a1a1aa', marginTop: '3px' }}>{item.username}</div>
                    <div style={{ fontSize: '0.725rem', color: '#f59e0b', marginTop: '6px', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                      {item.url}
                    </div>
                  </div>
                  <button
                    onClick={() => onSelect(item)}
                    style={{
                      backgroundColor: '#f59e0b',
                      border: 'none',
                      color: '#ffffff',
                      borderRadius: '6px',
                      padding: '8px 14px',
                      fontSize: '0.775rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                      flexShrink: 0,
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#d97706')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '#f59e0b')}
                  >
                    Select
                  </button>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};
